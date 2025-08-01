#
# Copyright 2020 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
CC = gcc-11
CPP = g++-11
AR = gcc-ar-11
GCOV = gcov-11
else
CC = gcc
CPP = g++
AR = ar
GCOV = gcov
endif

DB_API_LIBS = -lgmock -lgtest -lpthread -lOvsDbApi -ljansson
JSON_PARSER_API_LIBS = -lgmock -lgtest -lpthread -lOvsDbApi -ljansson
AGENT_API_LIBS = -lgmock -lgtest -lpthread -lOvsAgentApi
AGENT_LIBS = -lgmock -lgtest -lpthread -lOvsAction
INCLUDE = -I../include -I..
LDIR = -L.
ifeq ($(UNAME_S),Darwin)
INCLUDE += -I../test/include/ccsp -I$(INCDIR)
LDIR += -L$(LIBDIR)
endif

CFLAGS = -g -fPIC -fno-builtin -c --coverage
ifeq ($(UNAME_S),Darwin)
CFLAGS +=-DOVS_AGENT_API_LOG_FILE=\""/var/tmp/OvsAgentApiTest.log\""
CFLAGS +=-DOVSAGENT_DEBUG_ENABLE=\""/var/tmp/enable_ovs_debug\""
endif

CXXFLAGS = -g -fPIC -fno-builtin --coverage -std=c++11
ifeq ($(UNAME_S),Darwin)
CXXFLAGS +=-DOVS_AGENT_API_LOG_FILE=\""/var/tmp/OvsAgentApiTest.log\""
CXXFLAGS +=-DOVSAGENT_DEBUG_ENABLE=\""/var/tmp/enable_ovs_debug\""
endif

DB_API_TEST_APP = OvsDbApi_gtest.bin
AGENT_API_TEST_APP = OvsAgentApi_gtest.bin
AGENT_TEST_APP= OvsAgent_gtest.bin
JSON_PARSER_TEST_APP= JsonParser_gtest.bin

DB_API_DIR = ../OvsDbApi
DB_API_OBJ = $(patsubst %.c,%.o,$(wildcard $(DB_API_DIR)/**/*.c)) $(patsubst %.c,%.o,$(wildcard $(DB_API_DIR)/*.c))
DB_API_GCDA = $(patsubst %.c,%.gcda,$(wildcard $(DB_API_DIR)/**/*.c)) $(patsubst %.c,%.gcda,$(wildcard $(DB_API_DIR)/*.c))
DB_API_GCNO = $(patsubst %.c,%.gcno,$(wildcard $(DB_API_DIR)/**/*.c)) $(patsubst %.c,%.gcno,$(wildcard $(DB_API_DIR)/*.c))

ACT_DIR = ../OvsAction
ACT_SRC = $(ACT_DIR)/ovs_action.c
ACT_OBJ = $(patsubst %.c,%.o,$(ACT_SRC))
ACT_GCDA = $(patsubst %.c,%.gcda,$(ACT_SRC))
ACT_GCNO = $(patsubst %.c,%.gcno,$(ACT_SRC))

AGENT_API_DIR = ../OvsAgentApi
AGENT_API_OBJ = $(patsubst %.c,%.o,$(wildcard $(AGENT_API_DIR)/**/*.c)) $(patsubst %.c,%.o,$(wildcard $(AGENT_API_DIR)/*.c))
AGENT_API_GCDA = $(patsubst %.c,%.gcda,$(wildcard $(AGENT_API_DIR)/**/*.c)) $(patsubst %.c,%.gcda,$(wildcard $(AGENT_API_DIR)/*.c))
AGENT_API_GCNO = $(patsubst %.c,%.gcno,$(wildcard $(AGENT_API_DIR)/**/*.c)) $(patsubst %.c,%.gcno,$(wildcard $(AGENT_API_DIR)/*.c))

COM_DIR = ../common
COM_OBJ_C = $(patsubst %.c,%.o,$(wildcard $(COM_DIR)/**/*.c)) $(patsubst %.c,%.o,$(wildcard $(COM_DIR)/*.c))
COM_GCDA = $(patsubst %.c,%.gcda,$(wildcard $(COM_DIR)/**/*.c)) $(patsubst %.c,%.gcda,$(wildcard $(COM_DIR)/*.c))
COM_GCNO = $(patsubst %.c,%.gcno,$(wildcard $(COM_DIR)/**/*.c)) $(patsubst %.c,%.gcno,$(wildcard $(COM_DIR)/*.c))

MOCK_DIR = ../test/mocks
MOCK_SRC = $(wildcard $(MOCK_DIR)/*.cpp)
MOCK_OBJ = $(patsubst %.cpp,%.o,$(MOCK_SRC))
MOCK_GCDA = $(patsubst %.cpp,%.gcda,$(MOCK_SRC))
MOCK_GCNO = $(patsubst %.cpp,%.gcno,$(MOCK_SRC))

OVSDB_TEST_DIR = ../test/OvsDbApi
OVSDB_TEST_SRC = $(wildcard $(OVSDB_TEST_DIR)/*.cpp)
OVSDB_TEST_OBJ = $(patsubst %.cpp,%.o,$(OVSDB_TEST_SRC))
OVSDB_TEST_GCDA = $(patsubst %.cpp,%.gcda,$(OVSDB_TEST_SRC))
OVSDB_TEST_GCNO = $(patsubst %.cpp,%.gcno,$(OVSDB_TEST_SRC))

OVS_AGENT_API_TEST_DIR = ../test/OvsAgentApi
OVS_AGENT_API_TEST_SRC = $(wildcard $(OVS_AGENT_API_TEST_DIR)/*.cpp)
OVS_AGENT_API_TEST_OBJ = $(patsubst %.cpp,%.o,$(OVS_AGENT_API_TEST_SRC))
OVS_AGENT_API_TEST_GCDA = $(patsubst %.cpp,%.gcda,$(OVS_AGENT_API_TEST_SRC))
OVS_AGENT_API_TEST_GCNO = $(patsubst %.cpp,%.gcno,$(OVS_AGENT_API_TEST_SRC))

OVS_AGENT_TEST_DIR = ../test/OvsAgent
OVS_AGENT_TEST_SRC = $(wildcard $(OVS_AGENT_TEST_DIR)/*.cpp)
OVS_AGENT_TEST_OBJ = $(patsubst %.cpp,%.o,$(OVS_AGENT_TEST_SRC))
OVS_AGENT_TEST_GCDA = $(patsubst %.cpp,%.gcda,$(OVS_AGENT_TEST_SRC))
OVS_AGENT_TEST_GCNO = $(patsubst %.cpp,%.gcno,$(OVS_AGENT_TEST_SRC))

JSON_PARSER_TEST_DIR = ../test/JsonParser
JSON_PARSER_TEST_SRC = $(wildcard $(JSON_PARSER_TEST_DIR)/*.cpp)
JSON_PARSER_TEST_OBJ = $(patsubst %.cpp,%.o,$(JSON_PARSER_TEST_SRC))
JSON_PARSER_TEST_GCDA = $(patsubst %.cpp,%.gcda,$(JSON_PARSER_TEST_SRC))
JSON_PARSER_TEST_GCNO = $(patsubst %.cpp,%.gcno,$(JSON_PARSER_TEST_SRC))

ALL_OBJ = $(DB_API_OBJ) $(ACT_OBJ) $(AGENT_API_OBJ) $(MOCK_OBJ) $(OVSDB_TEST_OBJ) $(OVS_AGENT_API_TEST_OBJ) $(OVS_AGENT_TEST_OBJ) $(JSON_PARSER_TEST_OBJ) $(COM_OBJ_C)
ALL_GCOV = $(DB_API_GCDA) $(DB_API_GCNO) $(ACT_GCDA) $(ACT_GCNO) $(AGENT_API_GCDA) $(AGENT_API_GCNO) $(COM_GCDA) $(COM_GCNO) $(MOCK_GDCA) $(MOCK_GCNO) \
		$(OVSDB_TEST_GCDA) $(OVSDB_TEST_GCNO) $(OVS_AGENT_API_TEST_GCDA) $(OVS_AGENT_API_TEST_GCNO) $(OVS_AGENT_TEST_GCDA) $(OVS_AGENT_TEST_GCNO) \
		$(JSON_PARSER_TEST_GCNO) $(JSON_PARSER_TEST_GCDA)

all: tests html

tests: $(DB_API_TEST_APP) $(AGENT_API_TEST_APP) $(AGENT_TEST_APP) $(JSON_PARSER_TEST_APP)

$(DB_API_TEST_APP): libOvsDbApi.a $(OVSDB_TEST_SRC)
	$(CPP) $(CXXFLAGS) $(INCLUDE) $(LDIR) ../test/mocks/mock_ovsdb_socket.cpp $(OVSDB_TEST_SRC) -o $(DB_API_TEST_APP) $(DB_API_LIBS)

$(JSON_PARSER_TEST_APP): libOvsDbApi.a $(JSON_PARSER_TEST_SRC)
	$(CPP) $(CXXFLAGS) $(INCLUDE) $(LDIR) ../test/mocks/MockJsonParser.cpp $(JSON_PARSER_TEST_SRC) -o $(JSON_PARSER_TEST_APP) $(JSON_PARSER_API_LIBS)

$(AGENT_API_TEST_APP): libOvsAgentApi.a $(OVS_AGENT_API_TEST_SRC)
	$(CPP) $(CXXFLAGS) $(INCLUDE) $(LDIR) ../test/mocks/MockOvsDbApi.cpp $(OVS_AGENT_API_TEST_SRC) -o $(AGENT_API_TEST_APP) $(AGENT_API_LIBS)

$(AGENT_TEST_APP): libOvsAction.a $(OVS_AGENT_TEST_SRC)
	$(CPP) $(CXXFLAGS) $(INCLUDE) $(LDIR) ../test/mocks/mock_utils.cpp ../test/mocks/mock_file_io.cpp ../test/mocks/mock_syscfg.cpp ../test/mocks/mock_cosa_api.cpp \
	$(OVS_AGENT_TEST_SRC) -o $(AGENT_TEST_APP) $(AGENT_LIBS)

clean:
	rm -rf ./libOvs*.a $(DB_API_TEST_APP) $(AGENT_API_TEST_APP) $(AGENT_TEST_APP) $(JSON_PARSER_TEST_APP) $(ALL_OBJ) $(ALL_GCOV) ./*.info ./html ./*.gcda ./*.gcno ./*.dSYM

%.o : %.c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@

%.o : %.cpp
	$(CPP) $(CXXFLAGS) $(INCLUDE) $< -o $@

libOvsDbApi.a : $(DB_API_OBJ) $(COM_OBJ_C)
	$(AR) rcs libOvsDbApi.a $(DB_API_OBJ) $(COM_OBJ_C)

libOvsAgentApi.a : $(AGENT_API_OBJ) $(COM_OBJ_C)
	$(AR) rcs libOvsAgentApi.a $(AGENT_API_OBJ) $(COM_OBJ_C)

libOvsAction.a : $(ACT_OBJ) $(COM_OBJ_C)
	$(AR) rcs libOvsAction.a $(ACT_OBJ) $(COM_OBJ_C)

html:
	lcov --zerocounters --directory ../
	./$(DB_API_TEST_APP)
	lcov --capture --directory ../ --output-file OvsDbApi.info --test-name OvsDbApiTest --gcov-tool $(GCOV)
	lcov --extract OvsDbApi.info "`dirname \`pwd\``/*" --output-file OvsDbApi.info
	lcov --remove OvsDbApi.info "`dirname \`pwd\``/test/*" -o OvsDbApi.info
	lcov --zerocounters --directory ../
	./$(AGENT_API_TEST_APP)
	lcov --capture --directory ../ --output-file OvsAgentApi.info --test-name OvsAgentApiTest --gcov-tool $(GCOV)
	lcov --extract OvsAgentApi.info "`dirname \`pwd\``/*" --output-file OvsAgentApi.info
	lcov --remove OvsAgentApi.info "`dirname \`pwd\``/test/*" -o OvsAgentApi.info
	lcov --zerocounters --directory ../
	./$(AGENT_TEST_APP)
	lcov --capture --directory ../ --output-file OvsAgent.info --test-name OvsAgentTest --gcov-tool $(GCOV)
	lcov --extract OvsAgent.info "`dirname \`pwd\``/*" --output-file OvsAgent.info
	lcov --remove OvsAgent.info "`dirname \`pwd\``/test/*" -o OvsAgent.info
	./$(JSON_PARSER_TEST_APP)
	lcov --capture --directory ../ --output-file JsonParser.info --test-name JsonParserTest --gcov-tool $(GCOV)
	lcov --extract JsonParser.info "`dirname \`pwd\``/*" --output-file JsonParser.info
	lcov --remove JsonParser.info "`dirname \`pwd\``/test/*" -o JsonParser.info
	lcov --zerocounters --directory ../
	genhtml OvsDbApi.info OvsAgentApi.info OvsAgent.info JsonParser.info \
		--output-directory html --title "OVS Agent Unit Tests" \
		--show-details --legend
