// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_CONCEPT_CONCEPT_EDGE_H_
#define MUMBA_DOMAIN_CONCEPT_CONCEPT_EDGE_H_

#include "base/macros.h"

namespace domain {
class ConceptNode;

class ConceptEdge {
public:
  ConceptEdge();
  ~ConceptEdge();

  ConceptNode* source() const;
  ConceptNode* target() const;

  void set_source(ConceptNode* node);
  void set_target(ConceptNode* node);

private:

  DISALLOW_COPY_AND_ASSIGN(ConceptEdge);
};


}


#endif