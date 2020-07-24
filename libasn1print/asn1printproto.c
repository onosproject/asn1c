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
			case 4: // INTEGER
				INDENT("// int32 %s = 1 [(validate.rules).int32.const = ", expr->Identifier);
				safe_printf(" %d]; //", expr->value->value.v_integer);
				break;
			default:
				INDENT("// Error");
			}
			asn1print_ref(expr->reference, flags);
			safe_printf("\n");

			return 0;
		}
	} else if (expr->expr_type == ASN_BASIC_INTEGER && expr->meta_type == AMT_VALUESET) {
		INDENT("// int32 %s = 1 [(validate.rules).int32 = {in: [", expr->Identifier);
		if (expr->constraints != NULL && expr->constraints->elements) {
			struct asn1p_constraint_s *elements = *(expr->constraints->elements);
			safe_printf("%d", elements->value->value.v_integer);
			// TODO walk through the range of integers - like test 7 SameInterval
		}
		safe_printf("]}];\n");
		return 0;
	} else if (expr->expr_type == ASN_BASIC_INTEGER && expr->meta_type == AMT_TYPE) {
		INDENT("// int32 %s = 1 [(validate.rules).int32 = {", expr->Identifier);
		if (expr->constraints != NULL && expr->constraints->elements) {
			struct asn1p_constraint_s *elements = *(expr->constraints->elements);
			safe_printf("gte: %d, ", elements->range_start->value.v_integer);
			safe_printf("lte: %d}];\n", elements->range_stop->value.v_integer);
		} else {
			safe_printf("}];\n");
		}
		// TODO handle sub-elements like for test 07 Reason
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
