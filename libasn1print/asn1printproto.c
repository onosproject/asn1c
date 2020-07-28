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
#include <asn1p_value.h>
#include <asn1p_integer.h>
#include <asn1print.h>

#include "asn1printproto.h"

static abuf all_output_;

typedef enum {
    PRINT_STDOUT,
    GLOBAL_BUFFER,
} print_method_e;
static print_method_e print_method_;
static int asn1print_constraint_proto(const asn1p_constraint_t *ct, enum asn1print_flags2 flags);


#define	INDENT(fmt, args...)    do {        \
        if(!(flags & APF_NOINDENT2)) {       \
            int tmp_i = level;              \
            while(tmp_i--) safe_printf("    ");  \
        }                                   \
        safe_printf(fmt, ##args);                \
    } while(0)


/* Check printf's error code, to be pedantic. */
static int safe_printf(const char *fmt, ...) {
    int ret = 0;
    va_list ap;
    va_start(ap, fmt);

    switch(print_method_) {
    case PRINT_STDOUT:
        ret = vprintf(fmt, ap);
        break;
    case GLOBAL_BUFFER:
        ret = abuf_vprintf(&all_output_, fmt, ap);
        break;
    }
    assert(ret >= 0);
    va_end(ap);

    return ret;
}

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

int
asn1print_expr_proto(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr, enum asn1print_flags2 flags, int level) {
	asn1p_expr_t *se;
	int dont_involve_children = 0;
	int index = 0;

	if (mod != NULL) {
		// A dummy placeholder to avoid coverage errors
	}

	if(!expr->Identifier) return 0;

	if(flags & APF_LINE_COMMENTS2)
		INDENT("// #line %d \n", expr->_lineno);

	if (expr->expr_type == ASN_BASIC_ENUMERATED) {
		INDENT("enum %s {\n", expr->Identifier);
	} else if (expr->meta_type == AMT_VALUE) {
		if (expr->expr_type == ASN_BASIC_INTEGER) {
			INDENT("// int32 %s = 1 [(validate.rules).int32.const =", expr->Identifier);
			safe_printf(" %d];\n", expr->value->value.v_integer);
			return 0;
		} else if(expr->expr_type == A1TC_REFERENCE) {
			switch (expr->value->type) {
			case ATV_INTEGER: // INTEGER
				INDENT("// int32 %s = 1 [(validate.rules).int32.const = ", expr->Identifier);
				safe_printf(" %d]; //", expr->value->value.v_integer);
				break;
			case ATV_STRING:
				INDENT("// string %s = 1 [(validate.rules).string.const = ", expr->Identifier);
				safe_printf(" \"%s\"]; //", expr->value->value.string);
				break;
			default:
				INDENT("// Error");
			}
			asn1print_ref(expr->reference, (enum asn1print_flags) flags);
			safe_printf("\n");

			return 0;
		}
	} else if (expr->expr_type == ASN_BASIC_INTEGER && expr->meta_type == AMT_VALUESET) {
		INDENT("// int32 %s = 1 [(validate.rules).int32 = {in: [", expr->Identifier);
		asn1print_constraint_proto(expr->constraints, flags);
		safe_printf("]}];\n");
		return 0;
	} else if (expr->meta_type == AMT_TYPE && expr->expr_type != ASN_CONSTR_SEQUENCE) {
		switch (expr->expr_type) {
		case ASN_BASIC_INTEGER:
			INDENT("// int32 %s = 1 [(validate.rules).int32 = ", expr->Identifier);
			if (expr->constraints != NULL) {
				asn1print_constraint_proto(expr->constraints, flags);
			} else {
				safe_printf("{}");
				// TODO: Find why 07 test does not show Reason values
			}
			break;
		case ASN_STRING_IA5String:
		case ASN_STRING_BMPString:
			INDENT("// string %s = 1 [(validate.rules).string = {", expr->Identifier);
			asn1print_constraint_proto(expr->constraints, flags | APF_STRING_VALUE);
			break;
		case ASN_BASIC_BOOLEAN:
			INDENT("// bool %s = 1;\n", expr->Identifier);
			return 0;
		default:
			return 0;
		}
		safe_printf("];\n");
		return 0;
	} else if(expr->expr_type == A1TC_REFERENCE) {
		se = WITH_MODULE_NAMESPACE(expr->module, expr_ns, asn1f_find_terminal_type_ex(asn, expr_ns, expr));
		if(!se) {
			safe_printf(" (ANY)");
			return 0;
		}
		expr = se;
		dont_involve_children = 1;
	} else if (expr->expr_type == ASN_CONSTR_CHOICE) {
		level++;
		INDENT("oneof {\n");
	} else {
		INDENT("message %s {\n", expr->Identifier);
	}

	level++;
	if(TQ_FIRST(&expr->members)) {
		int extensible = 0;
		int hasEnumZero = 0;
		if(expr->expr_type == ASN_BASIC_BIT_STRING)
			dont_involve_children = 1;
		TQ_FOR(se, &(expr->members), next) {
			if (se->expr_type == ASN_BASIC_INTEGER) {
				INDENT("int32 ");
			} else if (se->expr_type == ASN_BASIC_BIT_STRING) {
				INDENT("BitString ");
			} else if (se->expr_type == ASN_BASIC_OBJECT_IDENTIFIER) {
				INDENT("BasicOid ");
			} else if (se->expr_type == ASN_CONSTR_SEQUENCE_OF) {
				INDENT("repeated ");
				safe_printf("TODO find reference ");
			} else if (se->expr_type == A1TC_REFERENCE && se->meta_type == AMT_TYPEREF) {
				struct asn1p_ref_component_s *comp = se->reference->components;
				if (se->reference->comp_count == 2) {
					INDENT("%s", (comp+1)->name);
				} else if (se->reference->comp_count == 1) {
					INDENT("%s", comp->name);
				}
			} else if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
				char *exprUc = toUpperSnakeCaseDup(expr->Identifier);
				if (hasEnumZero == 0) {
					if (se->value->type == ATV_INTEGER && se->value->value.v_integer != 0) {
						INDENT("%s_UNDEFINED = 0;\n", exprUc);
					}
					hasEnumZero = 1;
				}
				char *seUc = toUppercaseDup(se->Identifier);
				INDENT("%s_%s", exprUc, seUc);
				free(exprUc);
				free(seUc);
				if (se->value->type == ATV_INTEGER) {
					safe_printf(" = %d;\n", se->value->value.v_integer);
					continue;
				}
			}
			if(se->expr_type == A1TC_EXTENSIBLE) {
				extensible = 1;
				continue;
			} else if(se->expr_type == A1TC_REFERENCE) {
				INDENT("");
				// TODO: add this back in
//				asn1print_ref(se->reference, flags);
				if(se->Identifier)
					safe_printf(" %s", se->Identifier);
			} else if(se->Identifier) {
				INDENT("%s", se->Identifier);
			} else {
				safe_printf("UNHANDLED %s", se->expr_type);
			}
			safe_printf(" = %d;\n", ++index);
		}
		if(extensible) {
			INDENT("// Extensible\n");
		}
	}

	level--;
	if (expr->expr_type == ASN_CONSTR_CHOICE) {
		INDENT("}\n");
		level--;
	}

	safe_printf("}\n\n");

//	/*
//	 * Display the descendants (children) of the current type.
//	 */
	if(!dont_involve_children) {
//		TQ_FOR(se, &(expr->members), next) {
//			if(se->expr_type == A1TC_EXTENSIBLE) continue;
//			asn1print_expr_proto(asn, mod, se, flags, level + 1);
//		}
	}

	return 0;
}

static int
asn1print_constraint_proto(const asn1p_constraint_t *ct, enum asn1print_flags2 flags) {
	int symno = 0;
	int perhaps_subconstraints = 0;

	if(ct == 0) return 0;

	switch(ct->type) {
	case ACT_EL_TYPE:
		asn1print_value(ct->containedSubtype, (enum asn1print_flags) flags);
		perhaps_subconstraints = 1;
		break;
	case ACT_EL_VALUE:
		asn1print_value(ct->value, (enum asn1print_flags) flags);
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
				safe_printf("min_len: ");
			} else {
				safe_printf("gte: ");
			}
			break;
		case ACT_EL_LLRANGE:
		case ACT_EL_ULRANGE:
			if (flags & APF_STRING_VALUE) {
				safe_printf("min_len: ");
			} else {
				safe_printf("gt: ");
			}
			break;
		default: safe_printf("?..?"); break;
		}
		asn1print_value(ct->range_start, (enum asn1print_flags) flags);
		safe_printf(", ");
		switch(ct->type) {
		case ACT_EL_RANGE:
		case ACT_EL_LLRANGE:
			if (flags & APF_STRING_VALUE) {
				safe_printf("max_len: ");
			} else {
				safe_printf("lte: ");
			}
			break;
		case ACT_EL_RLRANGE:
		case ACT_EL_ULRANGE:
			if (flags & APF_STRING_VALUE) {
				safe_printf("max_len: ");
			} else {
				safe_printf("lt: ");
			}
			break;
		default: safe_printf("?..?"); break;
		}
		asn1print_value(ct->range_stop, (enum asn1print_flags) flags);
		break;
	case ACT_EL_EXT:
		break;
	case ACT_CT_SIZE:
	case ACT_CT_FROM:
		switch(ct->type) {
		case ACT_CT_SIZE: safe_printf(""); break;
		case ACT_CT_FROM: safe_printf("FROM"); break;
		default: safe_printf("??? "); break;
		}
		assert(ct->el_count != 0);
		assert(ct->el_count == 1);
		asn1print_constraint_proto(ct->elements[0], flags);
		break;
	case ACT_CT_WCOMP:
		assert(ct->el_count != 0);
		assert(ct->el_count == 1);
		safe_printf("WITH COMPONENT");
		perhaps_subconstraints = 1;
		break;
	case ACT_CT_WCOMPS: {
			unsigned int i;
			safe_printf("WITH COMPONENTS { ");
			for(i = 0; i < ct->el_count; i++) {
				asn1p_constraint_t *cel = ct->elements[i];
				if(i) safe_printf(", ");
				asn1print_constraint_proto(cel, flags);
				switch(cel->presence) {
				case ACPRES_DEFAULT: break;
				case ACPRES_PRESENT: safe_printf(" PRESENT"); break;
				case ACPRES_ABSENT: safe_printf(" ABSENT"); break;
				case ACPRES_OPTIONAL: safe_printf(" OPTIONAL");break;
				}
			}
			safe_printf(" }");
		}
		break;
	case ACT_CT_CTDBY:
		safe_printf("CONSTRAINED BY ");
		assert(ct->value->type == ATV_UNPARSED);
		safe_fwrite(ct->value->value.string.buf, ct->value->value.string.size);
		break;
	case ACT_CT_CTNG:
		safe_printf("CONTAINING ");
		asn1print_expr(ct->value->value.v_type->module->asn1p,
			ct->value->value.v_type->module,
			ct->value->value.v_type,
			(enum asn1print_flags) flags, 1);
		break;
	case ACT_CT_PATTERN:
		safe_printf("PATTERN ");
		asn1print_value(ct->value, (enum asn1print_flags) flags);
		break;
	case ACT_CA_SET: symno++;   /* Fall through */
	case ACT_CA_CRC: symno++;   /* Fall through */
	case ACT_CA_CSV: symno++;   /* Fall through */
	case ACT_CA_UNI: symno++;   /* Fall through */
	case ACT_CA_INT: symno++;   /* Fall through */
	case ACT_CA_EXC:
		{
			char *symtable[] = { " EXCEPT ", " ^ ", " | ", ",",
					"", "(" };
			unsigned int i;
            if(ct->type == ACT_CA_SET) safe_printf("{");
			for(i = 0; i < ct->el_count; i++) {
				if(i) safe_printf("%s", symtable[symno]);
				if(ct->type == ACT_CA_CRC) safe_printf("{");
				asn1print_constraint_proto(ct->elements[i], flags);
				if(ct->type == ACT_CA_CRC) safe_printf("}");
				if(ct->type == ACT_CA_SET && i+1 < ct->el_count)
					safe_printf("} ");
			}
            if(ct->type == ACT_CA_SET) safe_printf("}");
		}
		break;
	case ACT_CA_AEX:
		assert(ct->el_count == 1);
		safe_printf("ALL EXCEPT");
		perhaps_subconstraints = 1;
		break;
	case ACT_INVALID:
		assert(ct->type != ACT_INVALID);
		break;
	}

    if(perhaps_subconstraints && ct->el_count) {
        safe_printf(" ");
        assert(ct->el_count == 1);
        asn1print_constraint_proto(ct->elements[0], flags);
    }

	return 0;
}

// Replace any upper case chars with lower
void toLowercase(char *mixedCase) {
	int i = 0;
	while(mixedCase[i]) {
		(mixedCase)[i] = tolower(mixedCase[i]);
		i++;
	}
}

// Create new string with in lower case. Caller must free
char* toLowercaseDup(char *mixedCase) {
	char *mixedCaseDup = strdup(mixedCase);
	toLowercase(mixedCaseDup);
	return mixedCaseDup;
}

// Create new string with in lower_snake_case. Caller must free
char* toLowerSnakeCaseDup(char *mixedCase) {
	char *mixedCaseDup = strdup(mixedCase);
	toLowercase(mixedCaseDup);
	toSnakecase(mixedCaseDup);
	return mixedCaseDup;
}

// Replace any lower case chars with upper
void toUppercase(char *mixedCase) {
	int i = 0;
	while(mixedCase[i]) {
		(mixedCase)[i] = toupper(mixedCase[i]);
		i++;
	}
}

// Replace any punctuation chars with _
void toSnakecase(char *mixedCase) {
	int i = 0;
	while(mixedCase[i]) {
		switch (mixedCase[i]) {
		case '-':
		case '.':
			(mixedCase)[i] = '_';
		}
		i++;
	}
}

// Create new string with in upper case. Caller must free
// Any uppercase letters after the first one must be prefixed with '_'
char* toUpperSnakeCaseDup(const char *mixedCase) {
	int i = 0;
	int added = 0;
	char *upperSnakeCase = strdup(mixedCase);
	int origlen = strlen(mixedCase);
	while(mixedCase[i]) {
		if (i > 0 && mixedCase[i] >= 'A' && mixedCase[i] <= 'Z') {
			upperSnakeCase = (char *)realloc(upperSnakeCase, origlen + added + 1);
			upperSnakeCase[i+added] = '_';
			added++;
		}
		upperSnakeCase[i+added] = toupper(mixedCase[i]);
		i++;
	}
	upperSnakeCase[i+added] = '\0';

	return upperSnakeCase;
}

// Create new string with in upper case. Caller must free
char* toUppercaseDup(char *mixedCase) {
	char *mixedCaseDup = strdup(mixedCase);
	toUppercase(mixedCaseDup);
	return mixedCaseDup;
}

int startNotLcLetter(char *name) {
	if (name[0] < 'a' || name[0] > 'z') {
		return 1;
	}
	return 0;
}

void pathToPkg(char *pkg) {
	int i = 0;
	while(pkg[i]) {
		if (pkg[i] == '/') {
			(pkg)[i] = '.';
		}
		i++;
	}
}

char *removeRelPath(char *path) {
	int count = 0;
	char *newStart = path;
	while (strstr(newStart, "__/") != NULL) {
		if (strcmp(newStart, strstr(newStart, "__/")) == 0) {
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
