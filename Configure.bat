@mkdir build-x86 >nul
pushd build-x86 >nul
cmake -G "Visual Studio 12" ..\
popd >nul

@mkdir build-x64 >nul
pushd build-x64 >nul
cmake -G "Visual Studio 12 Win64" ..\
popd >nul