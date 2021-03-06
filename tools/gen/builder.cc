// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/builder.h"

#include <stddef.h>
#include <utility>

#include "gen/action_values.h"
#include "gen/config.h"
#include "gen/deps_iterator.h"
#include "gen/err.h"
#include "gen/loader.h"
#include "gen/pool.h"
#include "gen/scheduler.h"
#include "gen/settings.h"
#include "gen/target.h"
#include "gen/trace.h"

namespace {

typedef BuilderRecord::BuilderRecordSet BuilderRecordSet;

// Recursively looks in the tree for a given node, returning true if it
// was found in the dependecy graph. This is used to see if a given node
// participates in a cycle.
//
// If this returns true, the cycle will be in *path. This should point to an
// empty vector for the first call. During computation, the path will contain
// the full dependency path to the current node.
//
// Return false means no cycle was found.
bool RecursiveFindCycle(const BuilderRecord* search_in,
                        std::vector<const BuilderRecord*>* path) {
  path->push_back(search_in);
  for (auto* cur : search_in->unresolved_deps()) {
    std::vector<const BuilderRecord*>::iterator found =
        std::find(path->begin(), path->end(), cur);
    if (found != path->end()) {
      // This item is already in the set, we found the cycle. Everything before
      // the first definition of cur is irrelevant to the cycle.
      path->erase(path->begin(), found);
      path->push_back(cur);
      return true;
    }

    if (RecursiveFindCycle(cur, path))
      return true;  // Found cycle.
  }
  path->pop_back();
  return false;
}

}  // namespace

Builder::Builder(Loader* loader) : loader_(loader) {
}

Builder::~Builder() = default;

void Builder::ItemDefined(scoped_refptr<Item> item) {
  ScopedTrace trace(TraceItem::TRACE_DEFINE_TARGET, item->label());
  trace.SetToolchain(item->settings()->toolchain_label());

  BuilderRecord::ItemType type = BuilderRecord::TypeOfItem(item.get());

  Err err;
  BuilderRecord* record =
      GetOrCreateRecordOfType(item->label(), item->defined_from(), type, &err);
  if (!record) {
    g_scheduler->FailWithError(err);
    return;
  }

  // Check that it's not been already defined.
  if (record->item()) {
    err = Err(item->defined_from(), "Duplicate definition.",
        "The item\n  " + item->label().GetUserVisibleName(false) +
        "\nwas already defined.");
    err.AppendSubErr(Err(record->item()->defined_from(),
                         "Previous definition:"));
    g_scheduler->FailWithError(err);
    return;
  }

  record->set_item(std::move(item));

  // Do target-specific dependency setup. This will also schedule dependency
  // loads for targets that are required.
  switch (type) {
    case BuilderRecord::ITEM_TARGET:
      TargetDefined(record, &err);
      break;
    case BuilderRecord::ITEM_CONFIG:
      ConfigDefined(record, &err);
      break;
    case BuilderRecord::ITEM_TOOLCHAIN:
      ToolchainDefined(record, &err);
      break;
    default:
      break;
  }
  if (err.has_error()) {
    g_scheduler->FailWithError(err);
    return;
  }

  if (record->can_resolve()) {
    if (!ResolveItem(record, &err)) {
      g_scheduler->FailWithError(err);
      return;
    }
  }
}

scoped_refptr<Item> Builder::GetItem(const Label& label) const {
  const BuilderRecord* record = GetRecord(label);
  if (!record)
    return {};
  return record->item();
}

scoped_refptr<Toolchain> Builder::GetToolchain(const Label& label) const {
  const BuilderRecord* record = GetRecord(label);
  if (!record)
    return nullptr;
  if (!record->item())
    return nullptr;
  return record->item()->AsToolchain();
}

std::vector<const BuilderRecord*> Builder::GetAllRecords() const {
  std::vector<const BuilderRecord*> result;
  result.reserve(records_.size());
  for (const auto& record : records_)
    result.push_back(record.second.get());
  return result;
}

std::vector<Item*> Builder::GetAllResolvedItems() const {
  std::vector<Item*> result;
  result.reserve(records_.size());
  for (const auto& record : records_) {
    if (record.second->type() != BuilderRecord::ITEM_UNKNOWN &&
        record.second->should_generate() && record.second->item()) {
      result.push_back(record.second->item().get());
    }
  }

  return result;
}

std::vector<Target*> Builder::GetAllResolvedTargets() const {
  std::vector<Target*> result;
  result.reserve(records_.size());
  for (const auto& record : records_) {
    if (record.second->type() == BuilderRecord::ITEM_TARGET &&
        record.second->should_generate() && record.second->item())
      result.push_back(record.second->item()->AsTarget().get());
  }
  return result;
}

const BuilderRecord* Builder::GetRecord(const Label& label) const {
  // Forward to the non-const version.
  return const_cast<Builder*>(this)->GetRecord(label);
}

BuilderRecord* Builder::GetRecord(const Label& label) {
  auto found = records_.find(label);
  return (found != records_.end()) ? found->second.get() : nullptr;
}

bool Builder::CheckForBadItems(Err* err) const {
  // Look for errors where we find a defined node with an item that refers to
  // an undefined one with no item. There may be other nodes in turn depending
  // on our defined one, but listing those isn't helpful: we want to find the
  // broken link.
  //
  // This finds normal "missing dependency" errors but does not find circular
  // dependencies because in this case all items in the cycle will be GENERATED
  // but none will be resolved. If this happens, we'll check explicitly for
  // that below.
  std::vector<const BuilderRecord*> bad_records;
  std::string depstring;
  for (const auto& record_pair : records_) {
    const BuilderRecord* src = record_pair.second.get();
    if (!src->should_generate())
      continue;  // Skip ungenerated nodes.

    if (!src->resolved()) {
      bad_records.push_back(src);

      // Check dependencies.
      for (auto* dest : src->unresolved_deps()) {
        if (!dest->item()) {
          depstring += src->label().GetUserVisibleName(true) +
              "\n  needs " + dest->label().GetUserVisibleName(true) + "\n";
        }
      }
    }
  }

  if (!depstring.empty()) {
    *err = Err(Location(), "Unresolved dependencies.", depstring);
    return false;
  }

  if (!bad_records.empty()) {
    // Our logic above found a bad node but didn't identify the problem. This
    // normally means a circular dependency.
    depstring = CheckForCircularDependencies(bad_records);
    if (depstring.empty()) {
      // Something's very wrong, just dump out the bad nodes.
      depstring = "I have no idea what went wrong, but these are unresolved, "
          "possibly due to an\ninternal error:";
      for (auto* bad_record : bad_records) {
        depstring += "\n\"" +
            bad_record->label().GetUserVisibleName(false) + "\"";
      }
      *err = Err(Location(), "", depstring);
    } else {
      *err = Err(Location(), "Dependency cycle:", depstring);
    }
    return false;
  }

  return true;
}

bool Builder::TargetDefined(BuilderRecord* record, Err* err) {
  scoped_refptr<Target> target = record->item()->AsTarget();

  if (!AddDeps(record, target->public_deps(), err) ||
      !AddDeps(record, target->private_deps(), err) ||
      !AddDeps(record, target->data_deps(), err) ||
      !AddDeps(record, target->configs().vector(), err) ||
      !AddDeps(record, target->all_dependent_configs(), err) ||
      !AddDeps(record, target->public_configs(), err) ||
      !AddActionValuesDep(record, target->action_values(), err) ||
      !AddToolchainDep(record, target, err))
    return false;

  // All targets in the default toolchain get generated by default. We also
  // check if this target was previously marked as "required" and force setting
  // the bit again so the target's dependencies (which we now know) get the
  // required bit pushed to them.
  if (record->should_generate() || target->settings()->is_default())
    RecursiveSetShouldGenerate(record, true);

  return true;
}

bool Builder::ConfigDefined(BuilderRecord* record, Err* err) {
  scoped_refptr<Config> config = record->item()->AsConfig();
  if (!AddDeps(record, config->configs(), err))
    return false;

  // Make sure all deps of this config are scheduled to be loaded. For other
  // item types like targets, the "should generate" flag is propagated around
  // to mark whether this should happen. We could call
  // RecursiveSetShouldGenerate to do this step here, but since configs nor
  // anything they depend on is actually written, the "generate" flag isn't
  // relevant and means extra book keeping. Just force load any deps of this
  // config.
  for (auto* cur : record->all_deps())
    ScheduleItemLoadIfNecessary(cur);

  return true;
}

bool Builder::ToolchainDefined(BuilderRecord* record, Err* err) {
  scoped_refptr<Toolchain> toolchain = record->item()->AsToolchain();

  if (!AddDeps(record, toolchain->deps(), err))
    return false;

  for (int i = Toolchain::TYPE_NONE + 1; i < Toolchain::TYPE_NUMTYPES; i++) {
    Toolchain::ToolType tool_type = static_cast<Toolchain::ToolType>(i);
    Tool* tool = toolchain->GetTool(tool_type);
    if (!tool || tool->pool().label.is_null())
      continue;

    BuilderRecord* dep_record = GetOrCreateRecordOfType(
        tool->pool().label, tool->pool().origin, BuilderRecord::ITEM_POOL, err);
    if (!dep_record)
      return false;
    record->AddDep(dep_record);
  }

  // The default toolchain gets generated by default. Also propogate the
  // generate flag if it depends on items in a non-default toolchain.
  if (record->should_generate() ||
      toolchain->settings()->default_toolchain_label() == toolchain->label())
    RecursiveSetShouldGenerate(record, true);

  loader_->ToolchainLoaded(toolchain);
  return true;
}

BuilderRecord* Builder::GetOrCreateRecordOfType(const Label& label,
                                                const ParseNode* request_from,
                                                BuilderRecord::ItemType type,
                                                Err* err) {
  BuilderRecord* record = GetRecord(label);
  if (!record) {
    // Not seen this record yet, create a new one.
    auto new_record = std::make_unique<BuilderRecord>(type, label);
    new_record->set_originally_referenced_from(request_from);
    record = new_record.get();
    records_[label] = std::move(new_record);
    return record;
  }

  // Check types.
  if (record->type() != type) {
    std::string msg =
        "The type of " + label.GetUserVisibleName(false) +
        "\nhere is a " + BuilderRecord::GetNameForType(type) +
        " but was previously seen as a " +
        BuilderRecord::GetNameForType(record->type()) + ".\n\n"
        "The most common cause is that the label of a config was put in the\n"
        "in the deps section of a target (or vice-versa).";
    *err = Err(request_from, "Item type does not match.", msg);
    if (record->originally_referenced_from()) {
      err->AppendSubErr(Err(record->originally_referenced_from(),
                            std::string()));
    }
    return nullptr;
  }

  return record;
}

BuilderRecord* Builder::GetResolvedRecordOfType(const Label& label,
                                                const ParseNode* origin,
                                                BuilderRecord::ItemType type,
                                                Err* err) {
  BuilderRecord* record = GetRecord(label);
  if (!record) {
    *err = Err(origin, "Item not found",
        "\"" + label.GetUserVisibleName(false) + "\" doesn't\n"
        "refer to an existent thing.");
    return nullptr;
  }

  auto item = record->item();
  if (!item) {
    *err = Err(origin, "Item not resolved.",
        "\"" + label.GetUserVisibleName(false) + "\" hasn't been resolved.\n");
    return nullptr;
  }

  if (!BuilderRecord::IsItemOfType(item, type)) {
    *err = Err(origin,
        std::string("This is not a ") + BuilderRecord::GetNameForType(type),
        "\"" + label.GetUserVisibleName(false) + "\" refers to a " +
        item->GetItemTypeName() + " instead of a " +
        BuilderRecord::GetNameForType(type) + ".");
    return nullptr;
  }
  return record;
}

bool Builder::AddDeps(BuilderRecord* record,
                      const LabelConfigVector& configs,
                      Err* err) {
  for (const auto& config : configs) {
    BuilderRecord* dep_record = GetOrCreateRecordOfType(
        config.label, config.origin, BuilderRecord::ITEM_CONFIG, err);
    if (!dep_record)
      return false;
    record->AddDep(dep_record);
  }
  return true;
}

bool Builder::AddDeps(BuilderRecord* record,
                      const UniqueVector<LabelConfigPair>& configs,
                      Err* err) {
  for (const auto& config : configs) {
    BuilderRecord* dep_record = GetOrCreateRecordOfType(
        config.label, config.origin, BuilderRecord::ITEM_CONFIG, err);
    if (!dep_record)
      return false;
    record->AddDep(dep_record);
  }
  return true;
}

bool Builder::AddDeps(BuilderRecord* record,
                      const LabelTargetVector& targets,
                      Err* err) {
  for (const auto& target : targets) {
    BuilderRecord* dep_record = GetOrCreateRecordOfType(
        target.label, target.origin, BuilderRecord::ITEM_TARGET, err);
    if (!dep_record)
      return false;
    record->AddDep(dep_record);
  }
  return true;
}

bool Builder::AddActionValuesDep(BuilderRecord* record,
                                 const ActionValues& action_values,
                                 Err* err) {
  if (action_values.pool().label.is_null())
    return true;

  BuilderRecord* pool_record = GetOrCreateRecordOfType(
      action_values.pool().label, action_values.pool().origin,
      BuilderRecord::ITEM_POOL, err);
  if (!pool_record)
    return false;
  record->AddDep(pool_record);

  return true;
}

bool Builder::AddToolchainDep(BuilderRecord* record,
                              scoped_refptr<Target> target,
                              Err* err) {
  BuilderRecord* toolchain_record = GetOrCreateRecordOfType(
      target->settings()->toolchain_label(), target->defined_from(),
      BuilderRecord::ITEM_TOOLCHAIN, err);
  if (!toolchain_record)
    return false;
  record->AddDep(toolchain_record);

  return true;
}

void Builder::RecursiveSetShouldGenerate(BuilderRecord* record,
                                         bool force) {
  if (!record->should_generate()) {
    record->set_should_generate(true);

    // This may have caused the item to go into "resolved and generated" state.
    if (record->resolved() && !resolved_and_generated_callback_.is_null())
      resolved_and_generated_callback_.Run(record);
  } else if (!force) {
    return;  // Already set and we're not required to iterate dependencies.
  }

  for (auto* cur : record->all_deps()) {
    if (!cur->should_generate()) {
      ScheduleItemLoadIfNecessary(cur);
      RecursiveSetShouldGenerate(cur, false);
    }
  }
}

void Builder::ScheduleItemLoadIfNecessary(BuilderRecord* record) {
  const ParseNode* origin = record->originally_referenced_from();
  loader_->Load(record->label(),
                origin ? origin->GetRange() : LocationRange());
}

bool Builder::ResolveItem(BuilderRecord* record, Err* err) {
  DCHECK(record->can_resolve() && !record->resolved());

  if (record->type() == BuilderRecord::ITEM_TARGET) {
    scoped_refptr<Target> target = record->item()->AsTarget();
    if (!ResolveDeps(&target->public_deps(), err) ||
        !ResolveDeps(&target->private_deps(), err) ||
        !ResolveDeps(&target->data_deps(), err) ||
        !ResolveConfigs(&target->configs(), err) ||
        !ResolveConfigs(&target->all_dependent_configs(), err) ||
        !ResolveConfigs(&target->public_configs(), err) ||
        !ResolveActionValues(&target->action_values(), err) ||
        !ResolveToolchain(target, err))
      return false;
  } else if (record->type() == BuilderRecord::ITEM_CONFIG) {
    scoped_refptr<Config> config = record->item()->AsConfig();
    if (!ResolveConfigs(&config->configs(), err))
      return false;
  } else if (record->type() == BuilderRecord::ITEM_TOOLCHAIN) {
    scoped_refptr<Toolchain> toolchain = record->item()->AsToolchain();
    if (!ResolveDeps(&toolchain->deps(), err))
      return false;
    if (!ResolvePools(toolchain, err))
      return false;
  }

  record->set_resolved(true);

  if (!record->item()->OnResolved(err))
    return false;
  if (record->should_generate() && !resolved_and_generated_callback_.is_null())
    resolved_and_generated_callback_.Run(record);

  // Recursively update everybody waiting on this item to be resolved.
  for (BuilderRecord* waiting : record->waiting_on_resolution()) {
    DCHECK(waiting->unresolved_deps().find(record) !=
           waiting->unresolved_deps().end());
    waiting->unresolved_deps().erase(record);

    if (waiting->can_resolve()) {
      if (!ResolveItem(waiting, err))
        return false;
    }
  }
  record->waiting_on_resolution().clear();
  return true;
}

bool Builder::ResolveDeps(LabelTargetVector* deps, Err* err) {
  for (LabelTargetPair& cur : *deps) {
    DCHECK(!cur.ptr);

    BuilderRecord* record = GetResolvedRecordOfType(
        cur.label, cur.origin, BuilderRecord::ITEM_TARGET, err);
    if (!record)
      return false;
    cur.ptr = record->item()->AsTarget();
  }
  return true;
}

bool Builder::ResolveConfigs(UniqueVector<LabelConfigPair>* configs, Err* err) {
  for (const auto& cur : *configs) {
    DCHECK(!cur.ptr);

    BuilderRecord* record = GetResolvedRecordOfType(
        cur.label, cur.origin, BuilderRecord::ITEM_CONFIG, err);
    if (!record)
      return false;
    const_cast<LabelConfigPair&>(cur).ptr = record->item()->AsConfig();
  }
  return true;
}

bool Builder::ResolveToolchain(scoped_refptr<Target> target, Err* err) {
  BuilderRecord* record = GetResolvedRecordOfType(
      target->settings()->toolchain_label(), target->defined_from(),
      BuilderRecord::ITEM_TOOLCHAIN, err);
  if (!record) {
    *err = Err(target->defined_from(),
        "Toolchain for target not defined.",
        "I was hoping to find a toolchain " +
        target->settings()->toolchain_label().GetUserVisibleName(false));
    return false;
  }

  if (!target->SetToolchain(record->item()->AsToolchain(), err))
    return false;

  return true;
}

bool Builder::ResolveActionValues(ActionValues* action_values, Err* err) {
  if (action_values->pool().label.is_null())
    return true;

  BuilderRecord* record = GetResolvedRecordOfType(
      action_values->pool().label, action_values->pool().origin,
      BuilderRecord::ITEM_POOL, err);
  if (!record)
    return false;
  action_values->set_pool(LabelPtrPair<Pool>(record->item()->AsPool()));

  return true;
}

bool Builder::ResolvePools(scoped_refptr<Toolchain> toolchain, Err* err) {
  for (int i = Toolchain::TYPE_NONE + 1; i < Toolchain::TYPE_NUMTYPES; i++) {
    Toolchain::ToolType tool_type = static_cast<Toolchain::ToolType>(i);
    Tool* tool = toolchain->GetTool(tool_type);
    if (!tool || tool->pool().label.is_null())
      continue;

    BuilderRecord* record =
        GetResolvedRecordOfType(tool->pool().label, toolchain->defined_from(),
                                BuilderRecord::ITEM_POOL, err);
    if (!record) {
      *err = Err(tool->pool().origin, "Pool for tool not defined.",
                 "I was hoping to find a pool " +
                     tool->pool().label.GetUserVisibleName(false));
      return false;
    }

    tool->set_pool(LabelPtrPair<Pool>(record->item()->AsPool()));
  }

  return true;
}

std::string Builder::CheckForCircularDependencies(
    const std::vector<const BuilderRecord*>& bad_records) const {
  std::vector<const BuilderRecord*> cycle;
  if (!RecursiveFindCycle(bad_records[0], &cycle))
    return std::string();  // Didn't find a cycle, something else is wrong.

  std::string ret;
  for (size_t i = 0; i < cycle.size(); i++) {
    ret += "  " + cycle[i]->label().GetUserVisibleName(false);
    if (i != cycle.size() - 1)
      ret += " ->";
    ret += "\n";
  }

  return ret;
}
