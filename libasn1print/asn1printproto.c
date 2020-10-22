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
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>

#include <asn1parser.h>
#include <asn1fix_export.h>
#include <asn1p_integer.h>
#include <asn1print.h>

#include "asn1printproto.h"
#include "asn1prototypes.h"

static abuf all_output_;

char usual_class_identifiers[USUAL_CLASS_IDENTIFIERS][USUAL_CLASS_IDENTIFIER_LEN] = {
	{USUAL_CLASS_IDENTIFIER_1},
	{USUAL_CLASS_IDENTIFIER_2}
};

typedef enum {
    PRINT_STDOUT,
    GLOBAL_BUFFER,
} print_method_e;
static print_method_e print_method_;
static char *proto_constraint_print(const asn1p_constraint_t *ct, enum asn1print_flags2 flags);
static char *proto_value_print(const asn1p_value_t *val, enum asn1print_flags flags);
static int proto_process_enumerated(asn1p_expr_t *expr, proto_enum_t **protoenum);

static int proto_process_children(asn1p_expr_t *expr, proto_msg_t *msgdef, int repeated);
static int asn1extract_columns(asn1p_expr_t *expr,
		proto_msg_t **proto_msgs, size_t *proto_msg_count,
		char *mod_file);
static char *escapeQuotesDup(const char *original);

/* Pedantically check fwrite's return value. */
static size_t safe_fwrite(const void *ptr, size_t size) {
    size_t ret;

    switch(print_method_) {
    case PRINT_STDOUT:
        ret = fwrite(ptr, 1, size, stdout);
        assert(ret == size);
        break;
    case GLOBAL_BUFFER:
        abuf_add_bytes(&all_output_, ptr, size);
        ret = size;
        break;
    }

    return ret;
}

static char
*escapeQuotesDup(const char *original) {
	int origlen = strlen(original);
	char *escaped = strdup(original);
	int added = 0;
	int i = 0;
	while(original[i]) {
		if (original[i] == '\"') {
			escaped = (char *)realloc(escaped, (origlen + added + 1)*sizeof(char));
			escaped[i+added] = '\\';
			escaped[i+added+1] = original[i];
			added++;
		} else {
			escaped[i+added] = original[i];
		}
		i++;
	}
	escaped[origlen+added] = '\0';
	return escaped;
}

static proto_param_kind_e
proto_param_type(struct asn1p_param_s *param) {
    char *governer = param->governor->components->name;
    char *arg = param->argument;

    //    if (strlen(governer) == 0) {
//        // All caps means class/type
//        // Start with cap means type
//        // Start with cap means type
//    } else if (param->governor->components->lex_type == ){
//        // Start with lowercase means value
//        // Starts with upper case
//    }
    // FIXME: For now just discriminating between Type, Value and Value Set
    return !strlen(governer) ? PROTO_PARAM_TYPE
           : islower(arg[0]) ? PROTO_PARAM_VALUE
                             : PROTO_PARAM_VALUE_SET;
}

static char *
proto_extract_params(proto_msg_t *msg, asn1p_expr_t *expr) {
	char *params_comments = malloc(PROTO_COMMENTS_CHARS);
	memset(params_comments, 0, PROTO_COMMENTS_CHARS);
	char temp[PROTO_COMMENTS_CHARS] = {};
	for (int i=0; i < expr->lhs_params->params_count; i++ ){
		struct asn1p_param_s *param = &expr->lhs_params->params[i];
        proto_param_t *pp = malloc(sizeof(proto_param_t));
        memset(pp, 0, sizeof(proto_param_t));
        pp->kind = proto_param_type(param);
        strcpy(pp->name, param->argument);

        proto_msg_add_param(msg, pp);

		sprintf(temp, "\nParam %s:%s", param->governor->components->name, param->argument);
		strncat(params_comments, temp, PROTO_COMMENTS_CHARS-strlen(params_comments));
	}

	return params_comments;
}

int
asn1print_expr_proto(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr,
		proto_msg_t **message, size_t *messages, proto_enum_t **protoenum, size_t *enums,
		enum asn1print_flags2 flags) {
	if (mod != NULL) {
		// A dummy placeholder to avoid coverage errors
	}

	// If there are specializations (driven by parameters, define these as proto messages)
	if (expr->specializations.pspecs_count > 0) {
		int i;
		int ret;
		for (i=0; i<expr->specializations.pspecs_count; i++) {
			asn1p_expr_t* spec_clone = expr->specializations.pspec[i].my_clone;
			ret = asn1print_expr_proto(asn, mod, spec_clone, message, messages, protoenum, enums, flags);
			if (ret != 0) {
				return ret;
			}
		}
		return 0;
	};

	if(!expr->Identifier) return 0;

	if (expr->expr_type == ASN_BASIC_ENUMERATED) {
		proto_enum_t *newenum = proto_create_enum(expr->Identifier,
				"enumerated from %s:%d", mod->source_file_name, expr->_lineno);
		proto_process_enumerated(expr, &newenum);
		proto_enums_add_enum(protoenum, enums, newenum);

	} else if (expr->meta_type == AMT_VALUE) {
		proto_msg_t *msg;
		proto_msg_def_t *msgelem;
		switch (expr->expr_type) {
		case ASN_BASIC_INTEGER:
			msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
					"constant Integer from %s:%d", mod->source_file_name, expr->_lineno);
			msgelem = proto_create_msg_elem("value", "int32", NULL);
			sprintf(msgelem->rules, "int32.const = %d", (int)expr->value->value.v_integer);
			proto_msg_add_elem(msg, msgelem);
			proto_messages_add_msg(message, messages, msg);

			return 0;
		case ASN_BASIC_RELATIVE_OID:
			msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
					"constant Basic OID from %s:%d", mod->source_file_name, expr->_lineno);
			msgelem = proto_create_msg_elem("value", "string", NULL);
			sprintf(msgelem->rules, "string.const = '%s'", asn1f_printable_value(expr->value));
			proto_msg_add_elem(msg, msgelem);
			proto_messages_add_msg(message, messages, msg);

			break;
		case A1TC_REFERENCE:
			msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
					"reference from %s:%d", mod->source_file_name, expr->_lineno);
			msgelem = proto_create_msg_elem("value", "int32", NULL);

			for(size_t cc = 0; cc < expr->reference->comp_count; cc++) {
				if(cc) strcat(msgelem->comments, ".");
				strcat(msgelem->comments, expr->reference->components[cc].name);
			}

			switch (expr->value->type) {
			case ATV_INTEGER: // INTEGER
				sprintf(msgelem->rules, "int32.const = %d", (int)expr->value->value.v_integer);
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(message, messages, msg);
				return 0;
			case ATV_STRING:
				strcpy(msgelem->type, "string");
				char *escaped = escapeQuotesDup((char *)expr->value->value.string.buf);
				snprintf(msgelem->rules, 100, "string.const = \"%s\"", escaped);
				free(escaped);
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(message, messages, msg);
				return 0;
			case ATV_UNPARSED:
				if (expr->ioc_table != NULL) {
					asn1extract_columns(expr, message, messages, mod->source_file_name);
				}
				break;
			default:
				fprintf(stderr, "// Error. AMT_VALUE with ExprType: %d\n", expr->value->type);
			}

			return 0;
		default:
			fprintf(stderr, "ERROR: unhandled expr->expr_type %d\n", expr->expr_type);
			return -1;
		}
	} else if (expr->expr_type == ASN_BASIC_INTEGER && expr->meta_type == AMT_VALUESET) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
				"range of Integer from %s:%d", mod->source_file_name, expr->_lineno);
		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);
		char *constraints = proto_constraint_print(expr->constraints, flags);
		sprintf(msgelem->rules, "int32 = {in: [%s]}", constraints);
		free(constraints);
		proto_msg_add_elem(msg, msgelem);
		proto_messages_add_msg(message, messages, msg);

		return 0;
	} else if (expr->meta_type == AMT_TYPE &&
			expr->expr_type != ASN_CONSTR_SEQUENCE &&
			expr->expr_type != ASN_CONSTR_SEQUENCE_OF &&
			expr->expr_type != ASN_CONSTR_CHOICE) {

		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
				"range of Integer from %s:%d", mod->source_file_name, expr->_lineno);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);
		switch (expr->expr_type) {
		case ASN_BASIC_INTEGER:
			if (expr->constraints != NULL) {
				char *constraints = proto_constraint_print(expr->constraints, flags | APF_INT32_VALUE);
				sprintf(msgelem->rules, "int32 = {%s}", constraints);
				free(constraints);
				// TODO: Find why 07 test does not show Reason values
			}
			proto_msg_add_elem(msg, msgelem);
			proto_messages_add_msg(message, messages, msg);
			return 0;
		case ASN_STRING_IA5String:
		case ASN_STRING_BMPString:
			strcpy(msgelem->type, "string");
			if (expr->constraints != NULL) {
				char *constraints = proto_constraint_print(expr->constraints, flags | APF_STRING_VALUE);
				sprintf(msgelem->rules, "string = {%s}", constraints);
				free(constraints);
			}
			proto_msg_add_elem(msg, msgelem);
			proto_messages_add_msg(message, messages, msg);
			return 0;
		case ASN_BASIC_BOOLEAN:
			strcpy(msgelem->type, "bool");
			proto_msg_add_elem(msg, msgelem);
			proto_messages_add_msg(message, messages, msg);
			return 0;
		default:
			return 0;
		}
		return 0;
	} else if (expr->meta_type == AMT_TYPE &&
	    		(expr->expr_type == ASN_CONSTR_SEQUENCE ||
                    expr->expr_type == ASN_CONSTR_SEQUENCE_OF)) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
				"sequence from %s:%d", mod->source_file_name, expr->_lineno);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}
		proto_process_children(expr, msg, expr->expr_type == ASN_CONSTR_SEQUENCE_OF);

		proto_messages_add_msg(message, messages, msg);

    } else if (expr->meta_type == AMT_TYPE && expr->expr_type == ASN_CONSTR_CHOICE) {
        proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
                                                "sequence from %s:%d", mod->source_file_name, expr->_lineno);

        // TODO: Determine if comments should belong to the oneof or to the parent message.
        if (expr->lhs_params != NULL) {
            char *param_comments = proto_extract_params(msg, expr);
            strcat(msg->comments, param_comments);
            free(param_comments);
        }

        proto_msg_oneof_t *oneof = proto_create_msg_oneof(expr->Identifier,
                                                          "choice from %s:%d", mod->source_file_name, expr->_lineno);
        proto_msg_add_oneof(msg, oneof);

        proto_process_children(expr, (proto_msg_t *) oneof, 0);

        proto_messages_add_msg(message, messages, msg);

    } else if (expr->expr_type == A1TC_CLASSDEF) {
		// No equivalent of class in Protobuf - ignore
		return 0;

	} else if (expr->meta_type == AMT_TYPEREF) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
				"reference from %s:%d", mod->source_file_name, expr->_lineno);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);
		if (expr->reference->comp_count >= 1) {
			asn1p_expr_t *refElem;
			refElem = WITH_MODULE_NAMESPACE(expr->module, expr_ns, asn1f_find_terminal_type_ex(asn, expr_ns, expr));
			sprintf(msgelem->type, "%s%03d", refElem->Identifier, refElem->_type_unique_index);
		}
		proto_msg_add_elem(msg, msgelem);

		proto_messages_add_msg(message, messages, msg);
		return 0;

	} else if (expr->meta_type == AMT_VALUESET && expr->expr_type == A1TC_REFERENCE) {
		char refname[PROTO_NAME_CHARS] = {};
		if (expr->reference && expr->reference->comp_count > 0) {
			strcpy(refname, expr->reference->components[0].name);
		}
		asn1extract_columns(expr, message, messages, mod->source_file_name);
		return 0;
	} else {
		fprintf(stderr, "\n\n//////// ERROR Unhandled expr %s. Meta type: %d. Expr type: %d /////\n\n",
				expr->Identifier, expr->meta_type, expr->expr_type);
	}
	return 0;
}

static int
proto_process_enumerated(asn1p_expr_t *expr, proto_enum_t **protoenum) {
	asn1p_expr_t *se;
	TQ_FOR(se, &(expr->members), next) {
		if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
			proto_enum_def_t *def = proto_create_enum_def(se->Identifier, -1, NULL);
			if (se->value->type == ATV_INTEGER && se->value->value.v_integer >= 0) {
				def->index = se->value->value.v_integer;
			}
			proto_enum_add_def(*protoenum, def);
		}
	}
	return 0;
}

static int
proto_process_children(asn1p_expr_t *expr, proto_msg_t *msgdef, int repeated) {
	asn1p_expr_t *se;
	asn1p_expr_t *se2;

	if(TQ_FIRST(&expr->members)) {
		int extensible = 0;
//		if(expr->expr_type == ASN_BASIC_BIT_STRING)
//			dont_involve_children = 1;
		TQ_FOR(se, &(expr->members), next) {
			proto_msg_def_t *elem = proto_create_msg_elem(se->Identifier, "int32", NULL);
            elem->repeated = repeated;
			if (se->expr_type == ASN_BASIC_BIT_STRING) {
				strcpy(elem->type, "BitString");
			} else if (se->expr_type == ASN_BASIC_OBJECT_IDENTIFIER) {
				strcpy(elem->type, "BasicOid");
			} else if (se->expr_type == ASN_BASIC_BOOLEAN) {
				strcpy(elem->type, "bool");
			} else if (se->expr_type == ASN_STRING_UTF8String ||
					se->expr_type == ASN_STRING_TeletexString) {
				strcpy(elem->type, "string");
				if (se->constraints != NULL) {
					char *constraint = proto_constraint_print(se->constraints, APF_STRING_VALUE);
					sprintf(elem->rules, "string = {%s}", constraint);
					free(constraint);
				}
			} else if (se->meta_type == AMT_TYPE && se->expr_type == ASN_CONSTR_SEQUENCE_OF) {
				elem->repeated = 1;
				if (se->constraints != NULL) {
					char *constraint = proto_constraint_print(se->constraints, APF_REPEATED_VALUE);
					sprintf(elem->rules, "repeated = {%s}", constraint);
					free(constraint);
				}
				se2 = TQ_FIRST(&se->members); // Find the type
				if (se2->expr_type == A1TC_REFERENCE && se2->meta_type == AMT_TYPEREF) {
					if (se2->reference->comp_count == 1) {
						struct asn1p_ref_component_s *comp = se2->reference->components;
						strcpy(elem->type, comp->name);
					}
				} else {
					fprintf(stderr, "unhandled expr_type: %d and meta_type: %d in %s:%s \n",
							se->expr_type, se->meta_type, expr->Identifier, se->Identifier);
				}
			} else if (se->expr_type == A1TC_REFERENCE && se->meta_type == AMT_TYPEREF) {
				if (se->constraints &&
						se->constraints->type == ACT_CA_SET) {
					if (se->constraints->el_count == 1) {
						asn1p_constraint_t *el0 = se->constraints->elements[0];
						if (el0->type == ACT_CA_CRC) {
							for (int ct=0; ct < (int)el0->el_count; ct++) {
								asn1p_constraint_t *el00 = el0->elements[ct];
								if (el00->type == ACT_EL_VALUE && el00->value->type == ATV_REFERENCED) {
									asn1p_ref_t *objectSetRef = el00->value->value.reference;
									strcpy(elem->type, objectSetRef->components[0].name);
								} else if (el00->type == ACT_EL_VALUE && el00->value->type == ATV_VALUESET) {
									asn1p_constraint_t *valueSetConst = el00->value->value.constraint;
									strcpy(elem->type, asn1f_printable_value(valueSetConst->containedSubtype));
								} else {
									fprintf(stderr, "Unexpected constraint type: %d or value type %d\n",
											el00->type, el00->value->type);
									return -1;
								}
							}
						} else {
							fprintf(stderr, "expected CA_CRC constraint. Got: %d of %s:%s\n",
									el0->type, expr->Identifier, se->Identifier);
							return -1;
						}
					} else {
						fprintf(stderr, "Unexpected number of constraints in CA_SET: %d\n",
								se->combined_constraints->el_count);
						return -1;
					}
				} else {
					struct asn1p_ref_component_s *comp = se->reference->components;
					if (se->reference->comp_count == 2) {
						sprintf(elem->type, "%s", (comp+1)->name);
					} else if (se->reference->comp_count == 1) {
						strcpy(elem->type, comp->name);
					}
				}
			} else if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
				continue;
			}
			if(se->expr_type == A1TC_EXTENSIBLE) {
				extensible = 1;
				continue;
			} else if(se->expr_type == A1TC_REFERENCE) {
			} else if(se->Identifier) {
//				INDENT("%s", se->Identifier);
			} else {
//				safe_printf("UNHANDLED %s", se->expr_type);
			}
			proto_msg_add_elem(msgdef, elem);
//			safe_printf(" = %d;\n", ++index);
		}
		if(extensible) {
//			INDENT("// Extensible\n");
		}
	}

	return 0;
}

static char *
proto_constraint_print(const asn1p_constraint_t *ct, enum asn1print_flags2 flags) {
	int symno = 0;
	int perhaps_subconstraints = 0;
	char *result = malloc(1024 * sizeof(char));
	memset(result, 0, 1024);
	char* val = NULL;

	if(ct == 0) return 0;

	switch(ct->type) {
	case ACT_EL_TYPE:
		val = proto_value_print(ct->containedSubtype, (enum asn1print_flags) flags);
		strcat(result, val);
		free(val);
		perhaps_subconstraints = 1;
		break;
	case ACT_EL_VALUE:
		if (flags & APF_STRING_VALUE) {
			strcat(result, "min_len: ");
			val = proto_value_print(ct->value, (enum asn1print_flags) flags);
			strcat(result, val);
			free(val);
			strcat(result, ", max_len: ");
			val = proto_value_print(ct->value, (enum asn1print_flags) flags);
			strcat(result, val);
			free(val);
			break;
		}
		val = proto_value_print(ct->value, (enum asn1print_flags) flags);
		strcat(result, val);
		free(val);
		perhaps_subconstraints = 1;
		break;
	case ACT_EL_RANGE:
	case ACT_EL_LLRANGE:
	case ACT_EL_RLRANGE:
	case ACT_EL_ULRANGE:
		switch(ct->type) {
		case ACT_EL_RANGE:
		case ACT_EL_RLRANGE:
			if (flags & APF_STRING_VALUE) {
				strcat(result, "min_len: ");
			} else if (flags & APF_REPEATED_VALUE) {
				strcat(result, "min_items: ");
			} else {
				strcat(result, "gte: ");
			}
			break;
		case ACT_EL_LLRANGE:
		case ACT_EL_ULRANGE:
			if (flags & APF_STRING_VALUE) {
				strcat(result, "min_len: ");
			} else if (flags & APF_REPEATED_VALUE) {
				strcat(result, "min_items: ");
			} else {
				strcat(result, "gt: ");
			}
			break;
		default: strcat(result, "?..?"); break;
		}
		val = proto_value_print(ct->range_start, (enum asn1print_flags) flags);
		strcat(result, val);
		free(val);

		val = proto_value_print(ct->range_stop, (enum asn1print_flags) flags);
		if (strlen(val) == 0) {
			free(val);
			break;
		} else {
			strcat(result, ", ");
		}
		switch(ct->type) {
		case ACT_EL_RANGE:
		case ACT_EL_LLRANGE:
			if (flags & APF_STRING_VALUE) {
				strcat(result, "max_len: ");
			} else if (flags & APF_REPEATED_VALUE) {
				strcat(result, "max_items: ");
			} else {
				strcat(result, "lte: ");
			}
			break;
		case ACT_EL_RLRANGE:
		case ACT_EL_ULRANGE:
			if (flags & APF_STRING_VALUE) {
				strcat(result, "max_len: ");
			} else if (flags & APF_STRING_VALUE) {
				strcat(result, "max_items: ");
			} else {
				strcat(result, "lt: ");
			}
			break;
		default: strcat(result, "?..?"); break;
		}
		strcat(result, val);
		free(val);
		break;
	case ACT_EL_EXT:
		break;
	case ACT_CT_SIZE:
	case ACT_CT_FROM:
		switch(ct->type) {
		case ACT_CT_SIZE: break;
		case ACT_CT_FROM: strcat(result, "FROM"); break;
		default: strcat(result, "??? "); break;
		}
		assert(ct->el_count != 0);
		assert(ct->el_count == 1);
		char *add = proto_constraint_print(ct->elements[0], flags);
		strcat(result, add);
		free(add);
		break;
	case ACT_CT_WCOMP:
		assert(ct->el_count != 0);
		assert(ct->el_count == 1);
		strcat(result, "WITH COMPONENT");
		perhaps_subconstraints = 1;
		break;
	case ACT_CT_WCOMPS: {
			unsigned int i;
			strcat(result, "WITH COMPONENTS { ");
			for(i = 0; i < ct->el_count; i++) {
				asn1p_constraint_t *cel = ct->elements[i];
				if(i) strcat(result, ", ");
				char *add = proto_constraint_print(cel, flags);
				strcat(result, add);
				free(add);
				switch(cel->presence) {
				case ACPRES_DEFAULT: break;
				case ACPRES_PRESENT:
//					safe_printf(" PRESENT");
					break;
				case ACPRES_ABSENT:
//					safe_printf(" ABSENT");
					break;
				case ACPRES_OPTIONAL:
//					safe_printf(" OPTIONAL");
					break;
				}
			}
			strcat(result, " }");
		}
		break;
	case ACT_CT_CTDBY:
		strcat(result, "CONSTRAINED BY ");
		assert(ct->value->type == ATV_UNPARSED);
		safe_fwrite(ct->value->value.string.buf, ct->value->value.string.size);
		break;
	case ACT_CT_CTNG:
		strcat(result, "CONTAINING ");
		asn1print_expr(ct->value->value.v_type->module->asn1p,
			ct->value->value.v_type->module,
			ct->value->value.v_type,
			(enum asn1print_flags) flags, 1);
		break;
	case ACT_CT_PATTERN:
		strcat(result, "PATTERN ");
		asn1print_value(ct->value, (enum asn1print_flags) flags);
		break;
	case ACT_CA_SET: symno++;   /* Fall through */
	case ACT_CA_CRC: symno++;   /* Fall through */
	case ACT_CA_CSV: symno++;   /* Fall through */
	case ACT_CA_UNI: symno++;   /* Fall through */
	case ACT_CA_INT: symno++;   /* Fall through */
	case ACT_CA_EXC:
		{
			char *symtable[] = { " EXCEPT ", " ^ ", ",",
					"", "(" };
			unsigned int i;
//            if(ct->type == ACT_CA_SET) safe_printf("{");
			for(i = 0; i < ct->el_count; i++) {
				if(i) strcat(result, symtable[symno]);
				if(ct->type == ACT_CA_CRC) strcat(result, "{");
				char *add = proto_constraint_print(ct->elements[i], flags);
				strcat(result, add);
				free(add);
				if(ct->type == ACT_CA_CRC) strcat(result, "}");
				if(ct->type == ACT_CA_SET && i+1 < ct->el_count)
					strcat(result, "} ");
			}
//            if(ct->type == ACT_CA_SET) safe_printf("}");
		}
		break;
	case ACT_CA_AEX:
		assert(ct->el_count == 1);
		strcat(result, "ALL EXCEPT");
		perhaps_subconstraints = 1;
		break;
	case ACT_INVALID:
		assert(ct->type != ACT_INVALID);
		break;
	}

    if(perhaps_subconstraints && ct->el_count) {
    	strcat(result, " ");
        assert(ct->el_count == 1);
        char *add = proto_constraint_print(ct->elements[0], flags);
		strcat(result, add);
		free(add);
    }

	return result;
}

static int
asn1extract_columns(asn1p_expr_t *expr, proto_msg_t **proto_msgs, size_t *proto_msg_count,
		char *mod_file) {
	char comment[PROTO_COMMENTS_CHARS] = {};
	char msgname[PROTO_NAME_CHARS] = {};

	strcpy(comment, "concrete instance(s) of class ");
	if (expr->reference != NULL && expr->reference->comp_count > 0) {
		strcat(comment, expr->reference->components->name);
	}
	strcat(comment, " from \%s:\%d");
	strcat(msgname, "_");
	strcat(msgname, expr->Identifier);

	proto_msg_t *new_proto_msg = proto_create_message(msgname, expr->spec_index, expr->_type_unique_index, comment, mod_file, expr->_lineno);

	int rowIdx = 0;
	int colIdx = 0;
	char instanceName[PROTO_NAME_CHARS] = {};
	proto_msg_t *submsg = NULL;
	for (rowIdx = 0; rowIdx < (int)expr->ioc_table->rows; rowIdx++) {
		asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];
		if (expr->ioc_table->rows > 1) {
			sprintf(msgname, "%s%03d", expr->Identifier, rowIdx+1);
			submsg = proto_create_message(msgname, -1, 0, NULL, mod_file, expr->_lineno);
			proto_msg_add_nested(new_proto_msg, submsg);
		}
		for (colIdx = 0; colIdx < (int)table_row->columns; colIdx++) {
			struct asn1p_ioc_cell_s colij = table_row->column[colIdx];
			char temptype[PROTO_TYPE_CHARS] = {};
			char rules[PROTO_RULES_CHARS] = {};
			if (colij.value) {
				if (colij.value->value) {
					const char *pval = asn1f_printable_value(colij.value->value);
					switch (colij.value->value->type) {
					case ATV_INTEGER:
						strcpy(temptype, "int32");
						snprintf(rules, PROTO_RULES_CHARS, "int32.const = %d", (int)(colij.value->value->value.v_integer));
						break;
					case ATV_STRING:
					case ATV_UNPARSED:
						strcpy(temptype, "string");
						snprintf(rules, PROTO_RULES_CHARS, "string.const = '%s'", pval);
						break;
					case ATV_REFERENCED:
						snprintf(temptype, PROTO_TYPE_CHARS, "%s", colij.value->Identifier);
						break;
					default:
						fprintf(stderr, "Unhandled value type %d %s\n", colij.value->value->type, pval);
						return -1;
					}
				} else if (strcmp(colij.value->Identifier, "INTEGER") == 0) {
					strcpy(temptype, "int32");
				} else if (strcmp(colij.value->Identifier, "REAL") == 0) {
					strcpy(temptype, "float");
				} else {
					snprintf(temptype, PROTO_TYPE_CHARS, "%s", colij.value->Identifier);
				}
				char tempname[PROTO_NAME_CHARS] = {};
				snprintf(tempname, PROTO_NAME_CHARS, "%s", colij.field->Identifier);
				for (int u=0; u < USUAL_CLASS_IDENTIFIERS; u++ ) {
					if (strcmp(usual_class_identifiers[u], colij.field->Identifier) == 0) {
						sprintf(instanceName, "%s%s", expr->reference->components->name, asn1f_printable_value(colij.value->value));
						if (submsg) {
							sprintf(submsg->name, "%s%s", expr->Identifier, asn1f_printable_value(colij.value->value));
						}
						break;
					}
				}

				proto_msg_def_t *new_proto_msg_def = proto_create_msg_elem(tempname, temptype, rules);
				if (submsg) {
					proto_msg_add_elem(submsg, new_proto_msg_def);
				} else {
					proto_msg_add_elem(new_proto_msg, new_proto_msg_def);
				}
			}
		}
		if (submsg) {
			proto_msg_def_t *nested_msg_def = proto_create_msg_elem("test", msgname, NULL);
			if (strlen(instanceName) > 0) {
				strcpy(nested_msg_def->name, instanceName);
				sprintf(nested_msg_def->type, "%s", submsg->name);
			} else {
				sprintf(nested_msg_def->name, "instance%03d", rowIdx+1);
			}
			proto_msg_add_elem(new_proto_msg, nested_msg_def);
		}
	}

	proto_messages_add_msg(proto_msgs, proto_msg_count, new_proto_msg);
	return 0;
}

static char*
proto_value_print(const asn1p_value_t *val, enum asn1print_flags flags) {
	char *result = malloc(256*sizeof(char));
	memset(result, 0, 256);
	if(val == NULL)
		return result;

	char out[30] = {};

	switch(val->type) {
	case ATV_NOVALUE:
		break;
	case ATV_NULL:
		strcat(result, "NULL");
		return result;
	case ATV_REAL:
		sprintf(out, "%f", val->value.v_double);
		strcat(result, out);
		return result;
	case ATV_TYPE:
		strcat(result, "ERROR not yet implemented");
//		asn1print_expr(val->value.v_type->module->asn1p,
//			val->value.v_type->module,
//			val->value.v_type, flags, 0);
		return result;
	case ATV_INTEGER:
		strcat(result, asn1p_itoa(val->value.v_integer));
		return result;
	case ATV_MIN:
		strcat(result, "0");
		return result;
	case ATV_MAX:
		if (flags & 0x100) { // APF_INT32_VALUE
			sprintf(out, "%d", INT32_MAX);
			strcat(result, out);
			return result;
		}
//		safe_printf("MAX"); return 0;
		return result;
	case ATV_FALSE: strcat(result, "FALSE"); return result;
	case ATV_TRUE: strcat(result, "TRUE"); return result;
	case ATV_TUPLE:
		sprintf(out, "{%d, %d}",
			(int)(val->value.v_integer >> 4),
			(int)(val->value.v_integer & 0x0f));
		strcat(result, out);
		return result;
	case ATV_QUADRUPLE:
		sprintf(out, "{%d, %d, %d, %d}",
			(int)((val->value.v_integer >> 24) & 0xff),
			(int)((val->value.v_integer >> 16) & 0xff),
			(int)((val->value.v_integer >> 8) & 0xff),
			(int)((val->value.v_integer >> 0) & 0xff)
		);
		strcat(result, out);
		return result;
	case ATV_STRING:
		{
			char *p = (char *)val->value.string.buf;
			strcat(result, "\"");
			if(strchr(p, '"')) {
				/* Mask quotes */
				for(; *p; p++) {
					if(*p == '"') {
						sprintf(out, "%c", *p);
						strcat(result, out);
					}
					sprintf(out, "%c", *p);
					strcat(result, out);
				}
			} else {
				sprintf(out, "%c", *p);
				strcat(result, out);
			}
			strcat(result, "\"");
		}
		return result;
	case ATV_UNPARSED:
		strcat(result, (char *)val->value.string.buf);
		return result;
	case ATV_BITVECTOR: // @suppress("Symbol is not resolved")
		{
			uint8_t *bitvector;
			int bits;
			int i;

			bitvector = val->value.binary_vector.bits;
			bits = val->value.binary_vector.size_in_bits;

			strcat(result, "'");
			if(bits%8) {
				for(i = 0; i < bits; i++) {
					uint8_t uc;
					uc = bitvector[i>>3];
					sprintf(out, "%c", ((uc >> (7-(i%8)))&1)?'1':'0');
					strcat(result, out);
				}
				strcat(result, "'B");
			} else {
				char hextable[16] = "0123456789ABCDEF";
				for(i = 0; i < (bits>>3); i++) {
					sprintf(out, "%c", hextable[bitvector[i] >> 4]);
					strcat(result, out);
					sprintf(out, "%c", hextable[bitvector[i] & 0x0f]);
					strcat(result, out);
				}
				strcat(result, "'H");
			}
			return result;
		}
	case ATV_REFERENCED:
		for(size_t cc = 0; cc < val->value.reference->comp_count; cc++) {
			if(cc) strcat(result, ".");
			strcat(result, val->value.reference->components[cc].name);
		}
		break;
	case ATV_VALUESET:
//		return asn1print_constraint(val->value.constraint, flags);
		return result;
	case ATV_CHOICE_IDENTIFIER:
		strcat(result, val->value.choice_identifier.identifier);
		char *val1 = proto_value_print(val->value.choice_identifier.value, flags);
		strcat(result, val1);
		free(val1);
		return result;
	}

	assert(val->type || !"Unknown");

	return result;
}
