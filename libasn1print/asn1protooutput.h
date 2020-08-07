// Copyright 2020-present Open Networking Foundation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef LIBASN1PRINT_ASN1PROTOOUTPUT_H_
#define LIBASN1PRINT_ASN1PROTOOUTPUT_H_

#include "asn1prototypes.h"

#define PROTOSCALARTYPES "double,float,int32,int64,uint32,uint64,sint32,sint64,fixed32,fixed64,sfixed32,sfixed64,bool,string,bytes"

void proto_print_msg(proto_module_t *proto_module, enum asn1print_flags2 flags, int level, int andfree);

#endif /* LIBASN1PRINT_ASN1PROTOOUTPUT_H_ */
