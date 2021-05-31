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

#ifndef LIBASN1PRINT_ASN1PROTOTYPES_H_
#define LIBASN1PRINT_ASN1PROTOTYPES_H_

#include <asn1parser.h>

#define PROTO_NAME_CHARS 70
#define PROTO_TYPE_CHARS 70
#define PROTO_RULES_CHARS 100
#define PROTO_COMMENTS_CHARS 200
#define PROTO_PATH_CHARS 200

#define USUAL_CLASS_IDENTIFIERS 2
#define USUAL_CLASS_IDENTIFIER_LEN 20
#define USUAL_CLASS_IDENTIFIER_1 "&id"
#define USUAL_CLASS_IDENTIFIER_2 "&procedureCode"

#define TRUE 1

typedef enum {
    PROTO_PARAM_TYPE,
    PROTO_PARAM_VALUE,
    PROTO_PARAM_VALUE_SET,
    PROTO_PARAM_CLASS,
    PROTO_PARAM_OBJECT,
    PROTO_PARAM_OBJECT_SET
} proto_param_kind_e;

typedef struct proto_param_s {
    proto_param_kind_e kind;
    char name[PROTO_NAME_CHARS];
} proto_param_t;

typedef struct proto_tags_s {
	int optional;
	int sizeExt;
	int sizeLB;
	int sizeUB;
	int valueExt;
	int valueLB;
	int valueUB;
    int repeated;
} proto_tags_t;

typedef struct proto_msg_def_s {
	char type[PROTO_TYPE_CHARS];
	char name[PROTO_NAME_CHARS];
	char rules[PROTO_RULES_CHARS];
	char comments[PROTO_COMMENTS_CHARS];
	proto_tags_t tags;
    enum asn1p_expr_marker_e marker;
} proto_msg_def_t;

typedef struct proto_msg_oneof_s {
	char name[PROTO_NAME_CHARS];
	struct proto_msg_def_s **entry;
	size_t entries;
	char comments[PROTO_COMMENTS_CHARS]; // Include new lines if necessary
} proto_msg_oneof_t;

// A structure of the Protobuf message - simple case - no `oneof`
typedef struct proto_msg_s {
	char name[PROTO_NAME_CHARS];
	struct proto_msg_def_s **entry;
	size_t entries;
	struct proto_msg_oneof_s **oneof;
	size_t oneofs;
    struct proto_param_s **param;
    size_t params;
    struct proto_msg_s **nested;
    size_t nesteds;
	char comments[PROTO_COMMENTS_CHARS]; // Include new lines if necessary
	int isConstant;
} proto_msg_t;

typedef struct proto_enum_def_s {
	char name[PROTO_NAME_CHARS];
	int index;
	char comment[PROTO_COMMENTS_CHARS];
} proto_enum_def_t;

typedef struct proto_enum_s {
	char name[PROTO_NAME_CHARS];
	struct proto_enum_def_s **def;
	size_t defs;
	char comments[PROTO_COMMENTS_CHARS];
	int extensible;
} proto_enum_t;

typedef struct proto_import_s {
	char path[PROTO_PATH_CHARS];
	asn1p_oid_t *oid;
} proto_import_t;

// A structure of the Protobuf module (file)
typedef struct proto_module_s {
	char modulename[PROTO_NAME_CHARS];
	char srcfilename[PROTO_PATH_CHARS];
	asn1p_oid_t *oid;
	proto_msg_t **message;
	size_t messages;
	proto_enum_t **protoenum;
	size_t enums;
	proto_import_t **import;
	size_t imports;
	char comments[PROTO_COMMENTS_CHARS]; // Include new lines if necessary
} proto_module_t;

proto_enum_t *proto_create_enum(const char *name, const char *comment_fmt, char *src, const int line);
proto_enum_def_t *proto_create_enum_def(const char* name, const int index, const char *comment);
void proto_enum_add_def(proto_enum_t *protoenum, proto_enum_def_t *def);
void proto_enums_add_enum(proto_enum_t **protoenums, size_t *enums_count, proto_enum_t *protoenum);
proto_msg_t *proto_create_message(const char *name, int spec_index, int unique_idx, const char *comment_fmt, char *src, const int line, const int isConstant);
proto_msg_oneof_t *proto_create_msg_oneof(const char *name, const char *comment_fmt, char *src, const int line);
proto_msg_def_t *proto_create_msg_elem(const char *name, const char *type, const char *rules);
void proto_msg_add_param(proto_msg_t *msg, proto_param_t *param);
void proto_msg_add_elem(proto_msg_t *msg, proto_msg_def_t *elem);
void proto_msg_add_oneof(proto_msg_t *msg, proto_msg_oneof_t *oneof);
void proto_msg_add_nested(proto_msg_t *msg, proto_msg_t *nested);
void proto_oneof_add_elem(proto_msg_oneof_t *oneof, proto_msg_def_t *elem);
void proto_messages_add_msg(proto_msg_t **messages, size_t *message_count, proto_msg_t *msg);
proto_import_t *proto_create_import(const char *path, asn1p_oid_t *oid);
char *proto_remove_rel_path(char *path);
char *proto_remove_whole_path(char *path);
int tags_sum(proto_tags_t tags);

#endif /* LIBASN1PRINT_ASN1PROTOTYPES_H_ */
