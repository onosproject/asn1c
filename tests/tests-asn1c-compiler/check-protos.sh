#!/bin/bash

# Test diff(1) capabilities
diff -a . . 2>/dev/null && diffArgs="-a"		# Assume text files
diff -u . . 2>/dev/null && diffArgs="$diffArgs -u"	# Unified diff output

finalExitCode=0

if [ "$1" != "regenerate" ]; then
    set -e
fi

LAST_FAILED=""
print_status() {
    if [ -n "${LAST_FAILED}" ]; then
        echo "Error while processing $LAST_FAILED"
    fi
}

trap print_status EXIT

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"

for ref in ${top_srcdir}/tests/tests-asn1c-compiler/*.asn1.-B; do
	baseref=$(basename -- "$ref")
	reffilename=${baseref/%".-B"/""}
	csplit ${ref} --elide-empty-files --prefix ${top_builddir}/tests/tests-asn1c-compiler/${reffilename}. --suffix "%d.proto" -s '/\w\.proto ////////////' '{*}'
	refdir=${top_builddir}/tests/tests-asn1c-compiler/${baseref/%".asn1.-B"/""}
	mkdir -p ${refdir}
	for refproto in ${top_builddir}/tests/tests-asn1c-compiler/${reffilename}*.proto; do
		newname=`head -n 1 ${refproto} | grep '\w.proto' | awk 'BEGIN { FS = " "}; { print $2 }'`
		package=`grep "^package" ${refproto} | awk 'BEGIN { FS = " "}; { print $2 }' | awk 'BEGIN { FS = ";"}; { print $1 }'`
		packagedir=${package//"."/"/"}
		mkdir -p ${refdir}/${packagedir}
		mv ${refproto} ${refdir}/${packagedir}/${newname}
		echo "Linting protobuf ${refdir}/${packagedir}/${newname}"
	done

	cat << EOF > ${refdir}/buf.yaml
lint:
  use:
    - DEFAULT
    - FILE_LOWER_SNAKE_CASE
  except:
    - ENUM_ZERO_VALUE_SUFFIX
EOF

	ec=0
	buf check lint --input ${refdir} || ec=$?
	if [ $ec != 0 ]; then
		LAST_FAILED="${refdir} (from $src)"
		finalExitCode=$ec
	fi

	rm -rf ${refdir}

done

exit $finalExitCode
