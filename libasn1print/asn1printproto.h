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

#ifndef LIBASN1PRINT_ASN1PRINTPROTO_H_
#define LIBASN1PRINT_ASN1PRINTPROTO_H_

#include "asn1prototypes.h"

enum asn1print_flags2 {
	APF_NOFLAGS2,
	APF_NOINDENT2		= 0x01,	/* Disable indentation */
	APF_LINE_COMMENTS2	= 0x02, /* Include line comments */
	APF_PRINT_XML_DTD2	= 0x04,	/* Generate XML DTD */
	APF_PRINT_CONSTRAINTS2	= 0x08,	/* Explain constraints */
	APF_PRINT_CLASS_MATRIX2	= 0x10,	/* Dump class matrix */
	APF_PRINT_PROTOBUF2	= 0x20,	/* Generate Protobuf */
	APF_STRING_VALUE = 0x40, /* Dealing with a string rather than numeric - for min_len */
	APF_BYTES_VALUE = 0x80, /* Dealing with bytes rather than numeric - for min_bytes */
	APF_INT32_VALUE = 0x100, /* Dealing with int32 - for max*/
};

int asn1print_expr_proto(asn1p_module_t *mod, asn1p_expr_t *tc,
		proto_msg_t **message, size_t *messages, proto_enum_t **protoenum, size_t *enums,
		enum asn1print_flags2 flags);

#endif /* LIBASN1PRINT_ASN1PRINTPROTO_H_ */
