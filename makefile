SLib           = scapi.a
CPP_FILES     := $(wildcard src/*/*.cpp)
OBJ_FILES     := $(patsubst src/%.cpp,obj/%.o,$(CPP_FILES))
OUT_DIR        = obj obj/circuits obj/comm obj/infra obj/interactive_mid_protocols obj/primitives
INC            = -I../boost_1_60_0 -Ilib -Ilib/MiraclWin64/source
CPP_OPTIONS   := -std=c++11 $(INC)  -maes -mpclmul -DBOOST_LOG_DYN_LINK
$(COMPILE.cpp) = g++ -c $(CPP_OPTIONS) -o $@ $<

all:: directories $(SLib)

directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): $(OBJ_FILES)
	ar ru $@ $^ 
	ranlib $@

obj/circuits/%.o: src/circuits/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/comm/%.o: src/comm/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/infra/%.o: src/infra/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/interactive_mid_protocols/%.o: src/interactive_mid_protocols/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/primitives/%.o: src/primitives/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 

tests:: all
	$(Program)

clean::
	@echo "cleaning .obj files"
	@rm -rf $(OUT_DIR)
	@echo "cleaning lib"
	@rm -f $(SLib)
