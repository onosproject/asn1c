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

cat << EOF > prototool.yaml
protoc:
  version: 3.11.0
lint:
  group: google
EOF

trap print_status EXIT

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"

for ref in ${top_srcdir}/tests/tests-asn1c-compiler/*.asn1.-B; do
	reffilename=${ref##*/}
	refproto=${reffilename/%"-B"/"proto"}
	echo "Compiling protobuf ${refproto} into ${top_builddir}"
	cp ${ref} ${refproto}
	ec=0
	prototool lint ${refproto} || ec=$?
	if [ $ec != 0 ]; then
		LAST_FAILED="$ref (from $src)"
		finalExitCode=$ec
	fi
	rm -f ${refproto}
done

rm -f prototool.yaml

exit $finalExitCode
