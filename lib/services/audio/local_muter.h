// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_AUDIO_LOCAL_MUTER_H_
#define SERVICES_AUDIO_LOCAL_MUTER_H_

#include "base/callback.h"
#include "base/macros.h"
#include "base/sequence_checker.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "services/audio/group_coordinator.h"
#include "services/audio/public/mojom/stream_factory.mojom.h"

namespace audio {

class GroupMember;

// Mutes a group of streams, from construction time until destruction time. In
// between, LocalMuter ensures new group members are also muted. Holds all
// mojom::LocalMuter bindings.
class LocalMuter final : public mojom::LocalMuter, public GroupCoordinator::Observer {
 public:
  LocalMuter(GroupCoordinator* coordinator,
             const base::UnguessableToken& group_id);

  ~LocalMuter() final;

  const base::UnguessableToken& group_id() const { return group_id_; }

  // SetAllBindingsLostCallback() must be called before the first call to
  // AddBinding().
  void SetAllBindingsLostCallback(base::OnceClosure callback);
  void AddBinding(mojom::LocalMuterAssociatedRequest request);

  // GroupCoordinator::Observer implementation.
  void OnMemberJoinedGroup(GroupMember* member) final;
  void OnMemberLeftGroup(GroupMember* member) final;

 private:
  // Runs the |all_bindings_lost_callback_| when |bindings_| becomes empty.
  void OnBindingLost();

  GroupCoordinator* const coordinator_;
  const base::UnguessableToken group_id_;

  mojo::AssociatedBindingSet<mojom::LocalMuter> bindings_;
  base::OnceClosure all_bindings_lost_callback_;

  SEQUENCE_CHECKER(sequence_checker_);

  DISALLOW_COPY_AND_ASSIGN(LocalMuter);
};

}  // namespace audio

#endif  // SERVICES_AUDIO_LOCAL_MUTER_H_
