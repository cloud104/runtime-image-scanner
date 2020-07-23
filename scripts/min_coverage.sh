#!/bin/bash

MIN_COVERAGE=80

COVERAGE=$(coverage report | tail -n1 | awk '{print $4}' | sed 's/%//g')

if [ "$COVERAGE" -lt "$MIN_COVERAGE" ]; then
  echo "Please increase the code coverage. Actual coverage: $COVERAGE min coverage: $MIN_COVERAGE"
  exit 1
fi
