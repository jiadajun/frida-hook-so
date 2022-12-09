//===================内置方法下==========================================

const STD_STRING_SIZE = 3 * Process.pointerSize;

class StdString {
    constructor() {
        this.handle = Memory.alloc(STD_STRING_SIZE);
    }

    dispose() {
        const [data, isTiny] = this._getData();
        if (!isTiny) {
            Java.api.$delete(data);
        }
    }

    disposeToString() {
        const result = this.toString();
        this.dispose();
        return result;
    }

    toString() {
        const [data] = this._getData();
        return data.readUtf8String();
    }

    _getData() {
        const str = this.handle;
        const isTiny = (str.readU8() & 1) === 0;
        const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
        return [data, isTiny];
    }
}

function prettyMethod(method_id, withSignature) {
    const result = new StdString();
    Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
    return result.disposeToString();
}

function readStdString(str) {
    if ((str.readU8() & 1) === 1) { // size LSB (=1) indicates if it's a long string
        return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
    }
    return str.add(1).readUtf8String();
}

function jstring2Str(jstring) { //从frida_common_funs.js中copy出来
    var ret;
    Java.perform(function () {
        var String = Java.use("java.lang.String");
        ret = Java.cast(jstring, String);//jstring->String
    });
    return ret;
}

//===================内置方法上==========================================
function base() {
    console.log("cpu架构：", Process.arch, " | 指针大小：", Process.pointerSize, " | 策略：", Process.codeSigningPolicy, " | 进程id：", Process.id, " | 虚拟内存页面大小：", Process.pageSize, " | 系统：", Process.platform, " | 是否在调试：", Process.isDebuggerAttached())
}

function allModuleData(soName) {
    var getRunModule = Process.enumerateModules()
    for (var i = 0; i < getRunModule.length; i++) {
        var nullStr = ' .'
        for (var j = 0; j < (40 - getRunModule[i].name.length); j++) {
            nullStr = nullStr + '.'
        }
        if (soName) {
            if (getRunModule[i].name.indexOf(soName) > -1) {
                console.log("模块信息 ： base:", getRunModule[i].base, " | name:", getRunModule[i].name, nullStr, " | path:", getRunModule[i].path)
            }
        } else {
            console.log("模块信息 ： base:", getRunModule[i].base, " | name:", getRunModule[i].name, nullStr, " | path:", getRunModule[i].path)
        }
    }
    console.log("==================================================================================================")

}

function getSoAddr(soName) {
    var soAddr = Module.findBaseAddress(soName)
    console.log("当前模块 = ", soName, " 内存基指 ：", soAddr)

    console.log("==================================================================================================")

}

function enumerateImportsSync(soAddr, varName) {
    var imports = Module.enumerateImportsSync(soAddr);

    for (var i = 0; i < imports.length; i++) {
        var nullStr = ' .'
        for (var j = 0; j < (30 - imports[i].name.length); j++) {
            nullStr = nullStr + '.'
        }
        if (varName) {
            if (imports[i].name.indexOf(varName) > -1) {
                console.log("导入函数信息 : ", imports[i].name, nullStr, imports[i].address);
            }
        } else {
            console.log("导入函数信息 : ", imports[i].name, nullStr, imports[i].address);
        }
    }
    console.log("==================================================================================================")

}

function enumerateExportsSync(soAddr, varName) {
    var exports = Module.enumerateExportsSync(soAddr);

    for (var i = 0; i < exports.length; i++) {
        var nullStr = ' .'
        for (var j = 0; j < (70 - exports[i].name.length); j++) {
            nullStr = nullStr + '.'
        }
        if (varName) {
            if (exports[i].name.indexOf(varName) > -1) {
                console.log("导出函数信息 : ", exports[i].name, nullStr, exports[i].address);
            }
        } else {
            console.log("导出函数信息 : ", exports[i].name, nullStr, exports[i].address);
        }
    }
    console.log("==================================================================================================")

}

function hookFuncFromExports(soAddr, exportName) {
    var add_c_addr = Module.findExportByName(soAddr, exportName);
    console.log("导出函数的名native 基指 ：add_c_addr is :", add_c_addr);
    console.log("==================================================================================================")
}

function hookRegisterNative() {
    var libart = Process.findModuleByName('libart.so')
    var symbols = libart.enumerateSymbols()
    var ii = true //显示空格用的 无其他意义
    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name.indexOf('RegisterNative') > -1 && symbols[i].name.indexOf('ArtMethod') > -1 && symbols[i].name.indexOf('RuntimeCallbacks') < 0) {
            //art::RuntimeCallbacks::RegisterNativeMethod(art::ArtMethod*, void const*, void**)
            Interceptor.attach(symbols[i].address, {
                onEnter: function (args) {
                    this.arg0 = args[0]; // this
                },
                onLeave: function (retval) {
                    var modulemap = new ModuleMap()
                    modulemap.update()
                    var module = modulemap.find(retval)
                    var moduleSoAddr = Module.findBaseAddress(module.name)
                    // var string = Memory.alloc(0x100)
                    // ArtMethod_PrettyMethod(string, this.arg0, 1)
                    if (ii) {
                        console.log('----------------------------------------------------------------------')
                    }
                    ii = false
                    if (module != null) {
                        console.log('module_name : ', module.name, ' | 基指 : ', moduleSoAddr, ' | offset : ', ptr(retval).sub(module.base), ' | method_name : ', prettyMethod(this.arg0, 1))
                    } else {
                        console.log('<anonymous> method_name =>', readStdString(string), ', addr =>', ptr(retval))
                    }
                }
            });
        }
    }
}

function findFuncFromSymbols() {
    var NewStringUTF_addr = null;
    var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
    for (var i in symbols) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0
        ) {
            if (symbol.name.indexOf("NewStringUTF") >= 0) {
                console.log(">>>>>>>> 寻址native函数：find target symbols : ", symbol.name, " | address is : ", symbol.address);
                NewStringUTF_addr = symbol.address;
            }
        }
    }

    console.log(">>>>>>>> NewStringUTF_addr is ", NewStringUTF_addr);
    try {
        Interceptor.attach(NewStringUTF_addr, {
            onEnter: function (args) {
                try {
                    console.log("args0", args[0], hexdump(args[0]));
                    console.log("args1", args[1], hexdump(args[1]));
                    var env = Java.vm.tryGetEnv();
                    if (env != null) {
                        // 直接读取 c 里面的 char
                        console.log("直接读取 c 里面的 char ：Memory readCstring is :", Memory.readCString(args[1]));
                    } else {
                        console.log("get env error");
                    }
                } catch (e) {

                }

            },
            onLeave: function (returnResult) {
                try {
                    console.log("返回结果 >>>>> returnResult: ", jstring2Str(returnResult));
                    var env = Java.vm.tryGetEnv();
                    if (env != null) {
                        // var jstring = env.newStringUtf("修改返回值");
                        // returnResult.replace(ptr(jstring));
                    }
                } catch (e) {

                }

            }
        })
    } catch (e) {

    }
}

function findFuncFromExports(soAddr, funName) {
    var nativePointer = Module.findExportByName(soAddr, funName);
    console.log("模块名字：", soAddr, " | 方法名字：", funName, " | 当前方法的地址    :", nativePointer);
    Interceptor.attach(nativePointer, {
        //打印参数
        onEnter: function (args) {
            console.log("参数指针：", args[2], " | 参数字符串 ：", jstring2Str(args[2]))

        },
        onLeave: function (returnValue) {
            console.log("返回值指针：", returnValue, " | 返回值字符串：", jstring2Str(returnValue))
            // 修改返回值
            // returnValue.replace("1234567");
        }
    })
}

function findFuncFromAddr(soAddr, funAddr) {
    var nativePointer = Module.findBaseAddress(soAddr);
    var nativePointerFunc = nativePointer.add(funAddr)
    console.log("模块名字：", soAddr, " | 方法指针：", funAddr, " | 当前模块的地址    :", nativePointer, " | 当前方法的指针地址：", nativePointerFunc);
    Interceptor.attach(nativePointerFunc, {
        //打印参数
        onEnter: function (args) {
            console.log("参数指针：", args[2], " | 参数字符串 ：", jstring2Str(args[2]))
            // console.log(JSON.stringify(this.context))
        },
        onLeave: function (returnValue) {
            console.log("返回值指针：", returnValue, " | 返回值字符串：", jstring2Str(returnValue))
            //构造env，然后调用env.newStringUtf创建jstring （想知道env有哪些js方法可调用，看查看frida-java-master/lib/env.js 源码）
            var env = Java.vm.getEnv();
            var jstring = env.newStringUtf("frida hook native 你要的jstring");
            returnValue.replace(ptr(jstring));//修改返回值
            console.log("函数返回new值：", jstring2Str(returnValue));

        }
    })
}

function inlineHook(soAddr, funName, funAddr, is32) {
    var nativePointer = Module.findBaseAddress(soAddr);
    if (nativePointer) {
        var nativePointer1 = Module.findExportByName(soAddr, funName);
        var nativePointer2;
        if (is32) {
            nativePointer2 = nativePointer.add(funAddr + 1);
        } else {
            nativePointer2 = nativePointer.add(funAddr)
        }
        console.log("模块：", soAddr, " | 模块基指：", nativePointer, " | 函数名称：", funName, " | 函数基指：", nativePointer1, " | 函数偏移：", funAddr, " | 计算后的地址：", nativePointer2)

        // 主动调用
        var add1 = new NativeFunction(nativePointer1, "char", ["char"]);
        // var add2 = new NativeFunction(nativePointer2, "pointer", ["pointer"]);
        var input = "r0syue"
        var arg1 = Memory.allocUtf8String(input);

        console.log("add1 result is : ", add1("dddd"), " | add2 result is : ",)

//         由图中均可以看到，实参和返回类型都是const char* 类型,而且
//
// 1.第一个实参是待解密的字符串:"9YuQ2dk8CSaCe7DTAmaqAA=="
//
// 2.第二个实参就是AES的key:"thisisatestkey=="
//
// 直接使用这样的实参肯定是不行的，需要使用frida提供的方法进行构造:
//
// Memory.allocUtf8String
// 而读取const char* 类型的数据需要使用:
//
// Memory.readCString
//
    }

}

// 通俗点说, inline hook就是通过内存地址, 进行 hook;
function inline_hook() {
    var libnative_lib_addr = Module.findBaseAddress("libnative-lib.so");
    if (libnative_lib_addr) {
        console.log("libnative_lib_addr:", libnative_lib_addr);
        var addr_101F4 = libnative_lib_addr.add(0x102BC);
        console.log("addr_101F4:", addr_101F4);

        Java.perform(function () {
            Interceptor.attach(addr_101F4, {
                    onEnter: function (args) {
                        console.log("addr_101F4 OnEnter :", this.context.PC,
                            this.context.x1, this.context.x5,
                            this.context.x10);
                    },
                    onLeave: function (retval) {
                        console.log("retval is :", retval)
                    }
                }
            )
        })
    }
}

// so 层方法注册到js中，主动调用.cpp

function soReJsInline() {
    var baseAddr = Module.findBaseAddress("libnative-lib.so");
    console.log("baseAddr", baseAddr);
    var offset = 0x0000A28C + 1;
    var add_c_addr = baseAddr.add(offset);
    var add_c_func = new NativeFunction(add_c_addr, "int", ["int", "int"]);
    var result = add_c_func(1, 2);
    console.log(result);

    // 获取 so 文件基地址
    var base = Module.findBaseAddress("libnative-lib.so");
    // 获取目标函数偏移
    var sub_834_addr = base.add(0x835) // thumb 需要 +1
    // 使用 new NativeFunction 将函数注册到 js
    var sub_834 = new NativeFunction(sub_834_addr, 'pointer', ['pointer']);
    // 开辟内存, 创建入参
    var arg0 = Memory.alloc(10);
    ptr(arg0).writeUtf8String("123");
    var result = sub_834(arg0);
    console.log("result is :", hexdump(result));

}

// hook libart 中的jni 方法

function hook_libart() {
    var GetStringUTFChars_addr = null;

    // jni 系统函数都在 libart.so 中
    var module_libart = Process.findModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var name = symbols[i].name;
        if ((name.indexOf("JNI") >= 0)
            && (name.indexOf("CheckJNI") == -1)
            && (name.indexOf("art") >= 0)) {
            if (name.indexOf("GetStringUTFChars") >= 0) {
                console.log(name);
                // 获取到指定 jni 方法地址
                GetStringUTFChars_addr = symbols[i].address;
            }
        }
    }

    Java.perform(function () {
        Interceptor.attach(GetStringUTFChars_addr, {
            onEnter: function (args) {
                // console.log("args[0] is : ", args[0]);
                // console.log("args[1] is : ", args[1]);
                console.log("native args[1] is :", Java.vm.getEnv().getStringUtfChars(args[1], null).readCString());
                console.log('GetStringUTFChars onEnter called from:\n' +
                    Thread.backtrace(this.context, Backtracer.FUZZY)
                        .map(DebugSymbol.fromAddress).join('\n') + '\n');
                // console.log("native args[1] is :", Java.cast(args[1], Java.use("java.lang.String")));
                // console.log("native args[1] is :", Memory.readCString(Java.vm.getEnv().getStringUtfChars(args[1],null)));
            }, onLeave: function (retval) {
                // retval const char*
                console.log("GetStringUTFChars onLeave : ", ptr(retval).readCString());
            }
        })
    })
}

// hook libc

function hook_libc() {
    // var exports = Process.findModuleByName("libnative-lib.so").enumerateExports(); 导出
    // var imports = Process.findModuleByName("libnative-lib.so").enumerateImports(); 导入
    // var symbols = Process.findModuleByName("libnative-lib.so").enumerateSymbols(); 符号

    var pthread_create_addr = null;
    var symbols = Process.getModuleByName("libc.so").enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name === "pthread_create") {
            pthread_create_addr = symbol.address;
            console.log("pthread_create name is ->", symbol.name);
            console.log("pthread_create address is ->", pthread_create_addr);
        }
    }

    Java.perform(function () {
        // 定义方法 之后主动调用的时候使用
        var pthread_create = new NativeFunction(pthread_create_addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'])
        Interceptor.replace(pthread_create_addr, new NativeCallback(function (a0, a1, a2, a3) {
            var result = null;
            var detect_frida_loop = Module.findExportByName("libnative-lib.so", "_Z17detect_frida_loopPv");
            console.log("a0,a1,a2,a3 ->", a0, a1, a2, a3);
            if (String(a2) === String(detect_frida_loop)) {
                result = 0;
                console.log("阻止frida反调试启动");
            } else {
                result = pthread_create(a0, a1, a2, a3);
                console.log("正常启动");
            }
            return result;
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    })
}


function main_base_spawn() {
    console.log("####################################### spawn模式 ======= 开始 #####################################")

    //模块基础信息
    base()
    //通过 hook ArtMethod 的 RegisterNative 函数, 可以监控所有的静态注册和动态注册的 JNI 函数的地址;
    hookRegisterNative()
    //通过 symbols 符号定位 native 方法
    // findFuncFromSymbols()
}


function main_base_attach() {
    console.log("####################################### 附加模式 ======= 开始 ########################################")
    var soAddr = 'libxiaojianbang.so'
    //模块所有加载文件信息 参数 libroysue.so 不传是所有
    allModuleData(soAddr)
    //获取当前模块基指 参数 soAddr
    getSoAddr(soAddr)
    //枚举导入函数 指定的so 文件 和可选参数 特定的函数 (soAddr, '__memset_chk')
    enumerateImportsSync(soAddr)
    //枚举导出函数 指定的so 文件 和可选参数 特定的函数 (soAddr, '_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh')
    enumerateExportsSync(soAddr)

}

function main_hook_jni() {
    console.log("###################################################################################################")
}

function main_hook_attach_so() {
    console.log("####################################### 附加模式 ======= hook so ####################################")

    // 根据导出函数表 的函数来定位native 基指 (soAddr, '_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh')
    hookFuncFromExports(soAddr, "method01")
    //通过地址偏移 inline-hook 任意函数 主动调用
    inlineHook(soAddr, 'method01', '0x12bc', false)
    //通过 Intercept 拦截器打印 native 方法参数和返回值, 并修改返 == 对函数名hook
    findFuncFromExports(soAddr, 'method01')
    // 未导出的函数我们需要手动的计算出函数地址，然后将其转化成一个NativePointer的对象然后进行hook操作 函数地址 = so地址.add(偏移地址 + 1)  thumb和arm指令的区分，地址最后一位的奇偶性来进行标志
    findFuncFromAddr(soAddr, '0x12bc')

}


function mainAllTraceBase(soAddr) {
    main_base_spawn(soAddr)
    setTimeout(main_base_attach, 5000)
}


function main() {
    var soAddr = 'libxiaojianbang.so'
    mainAllTraceBase(soAddr)
    // hook 脚本
    //main_hook_attach_so

}


setImmediate(main)