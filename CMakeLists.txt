# CMakeList.txt: проект CMake для mirror_gun; включите исходный код и определения,
# укажите здесь логику для конкретного проекта.
#
cmake_minimum_required (VERSION 3.8)

project (mirror_gun)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTORCC ON) 
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
# Добавьте источник в исполняемый файл этого проекта.
add_executable (mirror_gun "mirror_gun.cpp" "mirror_gun.h" )
target_link_libraries(mirror_gun PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(mirror_gun PRIVATE spdlog::spdlog spdlog::spdlog_header_only)
# TODO: Добавьте тесты и целевые объекты, если это необходимо.
 include(InstallRequiredSystemLibraries)
 install(TARGETS mirror_gun 
   RUNTIME
   DESTINATION bin
   COMPONENT applications)
  install(FILES
            $<TARGET_FILE:spdlog::spdlog>
            DESTINATION bin COMPONENT applications)

set(CPACK_GENERATOR WIX)
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "CMake.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MyLib - CPack Component Installation Example")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Mirror Gun")
set(CPACK_PACKAGE_EXECUTABLES "mirror_gun" "Mirror Gun")
set(CPACK_WIX_CREATE_ICONS "YES")
set(CPACK_WIX_PROGRAM_MENU_FOLDER "MyProgram")
set(CPACK_WIX_SHORTCUTS_IN_START_MENU "ON")
set(CPACK_WIX_UI_REF "WixUI_Minimal")
set(CPACK_WIX_UPGRADE_GUID "CE2AF775-890C-4390-A173-9108AC28E88A")
set(CPACK_WIX_PRODUCT_ICON "${CMAKE_CURRENT_SOURCE_DIR}/icon.ico")
INCLUDE(CPack)

add_custom_command(
    TARGET mirror_gun
    POST_BUILD
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_CPACK_COMMAND}
    COMMENT "Выполняется кастомная команда после установки"
)
#add_dependencies(my_package install)