/*
 * Copyright (C) 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Matt Lilek <webkit@mattlilek.com>
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "core/shared/application/automation/inspector_database_resource.h"

#include "third_party/blink/renderer/modules/webdatabase/database.h"

namespace application {

static int g_next_unused_id = 1;

InspectorDatabaseResource* InspectorDatabaseResource::Create(
    blink::Database* database,
    const String& domain,
    const String& name,
    const String& version) {
  return new InspectorDatabaseResource(database, domain, name, version);
}

InspectorDatabaseResource::InspectorDatabaseResource(blink::Database* database,
                                                     const String& domain,
                                                     const String& name,
                                                     const String& version)
    : database_(database),
      id_(String::Number(g_next_unused_id++)),
      domain_(domain),
      name_(name),
      version_(version) {}

void InspectorDatabaseResource::Trace(blink::Visitor* visitor) {
  visitor->Trace(database_);
}

void InspectorDatabaseResource::Bind(automation::DatabaseClient* client) {
  automation::DatabasePtr json_object = automation::Database::New();
  json_object->id = std::string(id_.Utf8().data(), id_.length());
  json_object->domain = std::string(domain_.Utf8().data(), domain_.length());
  json_object->name = std::string(name_.Utf8().data(), name_.length());
  json_object->version = std::string(version_.Utf8().data(), version_.length());
  client->OnAddDatabase(std::move(json_object));
}

}  // namespace blink
