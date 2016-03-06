include ./rules/make.hdr

SLib = scapi.$(LIB_EXT)
CPP_FILES :=$(wildcard src/*/*.cpp)
OBJ_FILES := $(patsubst src/%.cpp,obj/%.$(OBJ_EXT),$(CPP_FILES))
OUT_DIR = obj obj/circuits obj/comm obj/infra obj/interactive_mid_protocols obj/primitives

CPP_OPTIONS:= -std=c++11 -I../../../../boost_1_60_0  -lcrypto++ -lcrypto -L/usr/lib -maes -mpclmul -DBOOST_LOG_DYN_LINK
CPP_LINK_OPTIONS:= -lcrypto++ -lcrypto

all:: directories $(SLib)

directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): $(OBJ_FILES)
	ar ru $@ $^ 
	ranlib $@

obj/circuits/%.$(OBJ_EXT): src/circuits/%.cpp
	$(COMPILE.cpp) 
obj/comm/%.$(OBJ_EXT): src/comm/%.cpp
	$(COMPILE.cpp) 
obj/infra/%.$(OBJ_EXT): src/infra/%.cpp
	$(COMPILE.cpp) 
obj/interactive_mid_protocols/%.$(OBJ_EXT): src/interactive_mid_protocols/%.cpp
	$(COMPILE.cpp) 
obj/primitives/%.$(OBJ_EXT): src/primitives/%.cpp
	$(COMPILE.cpp) 	

tests:: all
	$(Program)

clean::
	@echo "cleaning .obj files"
	@rm -rf $(OUT_DIR)
	@echo "cleaning lib"
	@rm -f $(SLib)
