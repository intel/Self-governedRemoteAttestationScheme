SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

App_Cpp_Files := app.cpp base64.cpp
App_Include_Paths := -I$(SGX_SDK)/include
App_Cpp_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

%.o: %.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_dcap_quoteverify -lcrypto -ljansson

app : $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"



clean:
	@rm -f app $(App_Cpp_Objects)
