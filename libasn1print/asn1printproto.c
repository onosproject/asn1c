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

#include "asn1printproto.h"

static abuf all_output_;

typedef enum {
    PRINT_STDOUT,
    GLOBAL_BUFFER,
} print_method_e;
static print_method_e print_method_;

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

int
asn1print_expr_proto(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr, enum asn1print_flags2 flags, int level) {
	asn1p_expr_t *se;
	int dont_involve_children = 0;
	int index = 0;

	if (mod != NULL) {
		// A dummy placeholder to avoid coverage errors
	}

	switch(expr->meta_type) {
	case AMT_TYPE:
	case AMT_OBJECTCLASS:
	case AMT_TYPEREF:
		break;
	default:
		if(expr->expr_type == A1TC_UNIVERVAL)
			break;
		return 0;
	}

	if(!expr->Identifier) return 0;

	if(flags & APF_LINE_COMMENTS2)
		INDENT("// #line %d \n", expr->_lineno);

	if (expr->expr_type == ASN_BASIC_ENUMERATED) {
		INDENT("enum %s {\n", expr->Identifier);
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
			} else if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
				char *exprUc = toUppercaseDup(expr->Identifier);
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
			INDENT("// Extensible ");
			if(expr->expr_type != ASN_CONSTR_SET
			&& expr->expr_type != ASN_CONSTR_CHOICE
			&& expr->expr_type != ASN_BASIC_INTEGER
			&& expr->expr_type != ASN_BASIC_ENUMERATED)
				safe_printf("*");
			safe_printf("\n");
		}

		if(expr->expr_type == ASN_CONSTR_SET)
			safe_printf("*");

	} else {
		switch(expr->expr_type) {

		case ASN_BASIC_BOOLEAN:
			safe_printf(" (true|false)");
			break;
		case ASN_CONSTR_CHOICE:
		case ASN_CONSTR_SET:
		case ASN_CONSTR_SET_OF:
		case ASN_CONSTR_SEQUENCE:
		case ASN_CONSTR_SEQUENCE_OF:
		case ASN_BASIC_NULL:
		case A1TC_UNIVERVAL:
			safe_printf(" EMPTY");
			break;
		case ASN_TYPE_ANY:
			safe_printf(" ANY");
			break;
		case ASN_BASIC_INTEGER:
			safe_printf(" int32");
			break;
		case ASN_BASIC_BIT_STRING:
		case ASN_BASIC_OCTET_STRING:
		case ASN_BASIC_OBJECT_IDENTIFIER:
		case ASN_BASIC_RELATIVE_OID:
		case ASN_BASIC_UTCTime:
		case ASN_BASIC_GeneralizedTime:
		case ASN_STRING_NumericString:
		case ASN_STRING_PrintableString:
			safe_printf(" (#PCDATA)");
			break;
		case ASN_STRING_VisibleString:
		case ASN_STRING_ISO646String:
			/* Entity references, but not XML elements may be present */
			safe_printf(" string");
			break;
		case ASN_BASIC_REAL:		/* e.g. <MINUS-INFINITY/> */
		case ASN_BASIC_ENUMERATED:	/* e.g. <enumIdentifier1/> */
		default:
			/*
			 * XML elements are allowed.
			 * For example, a UTF8String may contain "<bel/>".
			 */
			safe_printf(" ANY");
		}
		safe_printf(" value = %d;\n", ++index);
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

// Replace any lower case chars with upper
void toUppercase(char *mixedCase) {
	int i = 0;
	while(mixedCase[i]) {
		(mixedCase)[i] = toupper(mixedCase[i]);
		i++;
	}
}

// Create new string with in upper case. Caller must free
char* toUppercaseDup(char *mixedCase) {
	char *mixedCaseDup = strdup(mixedCase);
	toUppercase(mixedCaseDup);
	return mixedCaseDup;
}
