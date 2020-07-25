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

enum asn1print_flags2 {
	APF_NOFLAGS2,
	APF_NOINDENT2		= 0x01,	/* Disable indentation */
	APF_LINE_COMMENTS2	= 0x02, /* Include line comments */
	APF_PRINT_XML_DTD2	= 0x04,	/* Generate XML DTD */
	APF_PRINT_CONSTRAINTS2	= 0x08,	/* Explain constraints */
	APF_PRINT_CLASS_MATRIX2	= 0x10,	/* Dump class matrix */
	APF_PRINT_PROTOBUF2	= 0x20,	/* Generate Protobuf */
};

int asn1print_expr_proto(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *tc, enum asn1print_flags2 flags, int level);
void toLowercase(char *mixedCase);
void toSnakecase(char *mixedCase);
char *toLowercaseDup(char *mixedCase);
char *toLowerSnakeCaseDup(char *mixedCase);
void toUppercase(char *mixedCase);
char *toUppercaseDup(char *mixedCase);
int startNotLcLetter(char *name);
void pathToPkg(char *pkg);
char *removeRelPath(char *path);

#endif /* LIBASN1PRINT_ASN1PRINTPROTO_H_ */
