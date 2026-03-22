cmake_minimum_required(VERSION 3.17)
project(AegisAgent VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

find_package(nlohmann_json REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_package(Seastar REQUIRED)

# ====================
# 最新版 ONNX Runtime 配置 (本地绿色安装版)
# ====================
include_directories(${CMAKE_SOURCE_DIR}/third_party/onnxruntime/include)
link_directories(${CMAKE_SOURCE_DIR}/third_party/onnxruntime/lib)

# 3. 设置头文件搜索路径
include_directories(
    src 
    third_party/MCP-Server/include
    ${PCAP_INCLUDE_DIRS}
)

# 4. 收集源文件
file(GLOB_RECURSE SRC_FILES "src/*.cpp")
set(MCP_SERVER_SRC "third_party/MCP-Server/src/mcp/handlers/mcp_handler.cc")

# 5. 生成可执行文件
add_executable(aegis_agent ${SRC_FILES} ${MCP_SERVER_SRC})

# 6. 链接库
target_link_libraries(aegis_agent PRIVATE
    pthread 
    Seastar::seastar
    ${PCAP_LIBRARIES} 
    onnxruntime 
    nlohmann_json::nlohmann_json
)
