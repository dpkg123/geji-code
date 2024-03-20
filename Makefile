# SPDX-License-Identifier: Apache-2.0
# This file is part of src.
#
# Copyright (c) 2024 dpkg123
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CC = clang
CFLAGS += -D_FORTIFY_SOURCE=3 -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang -Wall -static -fstack-protector-all -z now -z noexecstack -fPIE -flto -Oz -o
SFLAGS = strip
UFLAGS = upx --best --ultra-brute $@

SRCS = $(wildcard *.c *.cpp)

OBJS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SRCS)))

%.o: %.c
	$(CC) $(CFLAGS)  $@ $<
	$(SFLAGS)  $@
	$(UFLAGS)

clean: *.o
	rm -rf *.o
