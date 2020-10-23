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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "asn1prototypes.h"

char *
proto_remove_rel_path(char *path) {
	int count = 0;
	char *newStart = path;
	while (strstr(newStart, "../") != NULL) {
		if (strcmp(newStart, strstr(newStart, "../")) == 0) {
			newStart = newStart+3;
			count++;
		}
	}
	while (count > 0) {
		if (strchr(newStart, '/') != NULL) {
			newStart = strchr(newStart, '/') + 1;
		}
		count--;
	}
	return newStart;
}

char *
proto_remove_whole_path(char *path) {
	return strrchr(path, '/') != NULL ? (strrchr(path, '/') + 1) : path;
}

proto_enum_t *
proto_create_enum(const char *name, const char *comment_fmt, char *src, const int line) {
	proto_enum_t *protoenum = malloc(sizeof(proto_enum_t));
	memset(protoenum, 0, sizeof(proto_enum_t));
	strcpy(protoenum->name, name);
	if (comment_fmt != NULL)
		sprintf(protoenum->comments, comment_fmt, proto_remove_whole_path(src), line);
	protoenum->def = calloc(0, sizeof(proto_enum_def_t *));
	protoenum->defs = 0;
	return protoenum;
}

proto_enum_def_t *
proto_create_enum_def(const char* name, const int index, const char *comment) {
	proto_enum_def_t *enumdef = malloc(sizeof(proto_enum_def_t));
	memset(enumdef, 0, sizeof(proto_enum_def_t));
	strcpy(enumdef->name, name);
	if (comment != NULL && strlen(comment) != 0) {
		strcpy(enumdef->comment, comment);
	}
	enumdef->index = index;
	return enumdef;
}

void
proto_enum_add_def(proto_enum_t *protoenum, proto_enum_def_t *def) {
	size_t existing_defs = protoenum->defs;
	protoenum->def = realloc(protoenum->def, (existing_defs + 1)*sizeof(proto_enum_def_t *));
	protoenum->def[existing_defs] = def;
	protoenum->defs = existing_defs + 1;
}

void
proto_enums_add_enum(proto_enum_t **protoenums, size_t *enums_count, proto_enum_t *protoenum) {
	size_t existing_count = *enums_count;
	protoenums = realloc(protoenums, (existing_count + 1)*sizeof(proto_enum_t *));
	protoenums[existing_count] = protoenum;
	*enums_count = existing_count + 1;
}

proto_msg_oneof_t *
proto_create_msg_oneof(const char *name, const char *comment_fmt, char *src, const int line) {
    proto_msg_oneof_t *msg = malloc(sizeof(proto_msg_oneof_t));
    memset(msg, 0, sizeof(proto_msg_oneof_t));
    strcpy(msg->name, name);
    if (comment_fmt != NULL) {
        sprintf(msg->comments, comment_fmt, proto_remove_whole_path(src), line);
    }
    msg->entry = calloc(0, sizeof(proto_msg_def_t *));
    msg->entries = 0;
    return msg;
}

proto_msg_t *
proto_create_message(const char *name, int spec_index, int unique_idx, const char *comment_fmt, char *src, const int line) {
	proto_msg_t *msg = malloc(sizeof(proto_msg_t));
	memset(msg, 0, sizeof(proto_msg_t));
	if (spec_index > -1) {
		snprintf(msg->name, PROTO_NAME_CHARS, "%s%03d", name, unique_idx);
	} else {
		strcpy(msg->name, name);
	}
	if (comment_fmt != NULL) {
		sprintf(msg->comments, comment_fmt, proto_remove_whole_path(src), line);
	}
	msg->entry = calloc(0, sizeof(proto_msg_def_t *));
	msg->entries = 0;
	msg->nested = calloc(0, sizeof(proto_msg_t *));
	msg->nesteds = 0;
	return msg;
}

proto_msg_def_t *
proto_create_msg_elem(const char *name, const char *type, const char *rules) {
	proto_msg_def_t *msgelem = malloc(sizeof(proto_msg_def_t));
	memset(msgelem, 0, sizeof(proto_msg_def_t));
    if (name) {
        strcpy(msgelem->name, name);
    } else {
        strcpy(msgelem->name, "value");
    }
    strcpy(msgelem->type, type);
	if (rules != NULL)
		strcpy(msgelem->rules, rules);
	return msgelem;
}

void
proto_msg_add_param(proto_msg_t *msg, proto_param_t *param) {
    size_t existing_params = msg->params;
    msg->param = realloc(msg->param, (existing_params + 1)*sizeof(proto_param_t *));
    msg->param[existing_params] = param;
    msg->params = existing_params + 1;
}

void
proto_msg_add_elem(proto_msg_t *msg, proto_msg_def_t *elem) {
	size_t existing_elems = msg->entries;
	msg->entry = realloc(msg->entry, (existing_elems + 1)*sizeof(proto_msg_def_t *));
	msg->entry[existing_elems] = elem;
	msg->entries = existing_elems + 1;
}

void
proto_msg_add_oneof(proto_msg_t *msg, proto_msg_oneof_t *oneof) {
    size_t existing_oneofs = msg->oneofs;
    msg->oneof = realloc(msg->oneof, (existing_oneofs + 1)*sizeof(proto_msg_oneof_t *));
    msg->oneof[existing_oneofs] = oneof;
    msg->oneofs = existing_oneofs + 1;
}

void proto_oneof_add_elem(proto_msg_oneof_t *oneof, proto_msg_def_t *elem) {
    size_t existing_elems = oneof->entries;
    oneof->entry = realloc(oneof->entry, (existing_elems + 1)*sizeof(proto_msg_def_t *));
    oneof->entry[existing_elems] = elem;
    oneof->entries = existing_elems + 1;
}

void
proto_messages_add_msg(proto_msg_t **messages, size_t *message_count, proto_msg_t *msg) {
	size_t existing_count = *message_count;
	messages = realloc(messages, (existing_count + 1)*sizeof(proto_msg_t *));
	messages[existing_count] = msg;
	*message_count = existing_count + 1;
}

void proto_msg_add_nested(proto_msg_t *msg, proto_msg_t *nested) {
	size_t existing_nesteds = msg->nesteds;
	msg->nested = realloc(msg->nested, (existing_nesteds + 1)*sizeof(proto_msg_t *));
	msg->nested[existing_nesteds] = nested;
	msg->nesteds = existing_nesteds + 1;
}

proto_import_t *
proto_create_import(const char *path, asn1p_oid_t *oid) {
	proto_import_t *protoimport = malloc(sizeof(proto_import_t));
	memset(protoimport, 0, sizeof(proto_import_t));
	strcpy(protoimport->path, path);
	if (oid != NULL)
		protoimport->oid = oid;
	return protoimport;
}
