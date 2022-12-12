// 枚举内存中的so文件
function hook01() {
    var modules = Process.enumerateModules();
    var getModule
    for (var i in modules) {
        var module = modules[i];
        console.log("module base : ", module.base, "  name :", module.name);
        if (module.name.indexOf("xiao") > -1) {
            getModule = module
        }
    }
    if (getModule) {
        console.log("hook01 指定文件打印 = ", "base : ", getModule.base, "  name :", getModule.name)

    }
}

// 获取指定文件的so 内存地址
function hook02() {
    var soAddr = Module.getBaseAddress('libbase.so');
    console.log("指定so文件获取基址 ： ", soAddr); //指定so文件获取基址 ：  0x7cb5749000
}

// 通过导出函数名定位 native方法
function hook03() {
    var add_c_addr = Module.getExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    console.log("通过导出函数名定位 获取函数的基址 ：", add_c_addr);//通过导出函数名定位 获取函数的基址 ： 0x7c174d7868
}

// 通过symbols 符号 定位 native 方法
function hook04() {
    var NewStringUTF_addr
    var symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    for (var i in symbols) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 && symbol.name.indexOf("JNI") >= 0 && symbol.name.indexOf("CheckJNI") < 0) {
            //console.log("symbols[i] :",JSON.stringify(symbols[i]))
            if (symbol.name.indexOf("NewStringUTF") >= 0) {
                console.log("find target symbols", symbol.name, "address is ", symbol.address);
                NewStringUTF_addr = symbol
            }
        }
    }

    console.log("NewStringUTF_addr is ", JSON.stringify(NewStringUTF_addr));
    Interceptor.attach(NewStringUTF_addr.address, {
        onEnter: function (args) {
            console.log("打印参数：", args[0], args[1])
            console.log("args[0] :", hexdump(args[0]))
            console.log("args[1] :", hexdump(args[1]))
            var env = Java.vm.tryGetEnv();
            if (env != null) {
                // 直接读取 c 里面的 char
                // console.log("Memory readCstring is  args[0]:", Memory.readCString(args[0]));
                console.log("Memory readCstring is  args[1]:", Memory.readCString(args[1]));

            } else {
                console.log("get env error");
            }
        }, onLeave: function (retval) {
            console.log("retval :", retval);//retval : 0x79
            var jString = Java.cast(retval, Java.use("java.lang.String"));
            console.log("retval = ", jString);
            var env = Java.vm.tryGetEnv();
            if (env != null) {
                var jstring = env.newStringUtf("xiuxiu");
                retval.replace(ptr(jstring));
            }
        }
    })

}

// 通过地址偏移inline-hook 任意函数
function hook05() {
    var so_addr = Module.getBaseAddress("libxiaojianbang.so");
    console.log("so_addr : ", so_addr);//so_addr :  0x7c1ae17000
    if (so_addr) {
        var so_func_add1 = Module.getExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
        console.log("so_func_add1 = ", so_func_add1);//so_func_add1 =  0x7c1ae19868
        var so_func_add2 = so_addr.add(0x2868);
        console.log("so_func_add2 = ", so_func_add2);//so_func_add2 =  0x7c1ae19868
    }
    //主动调用
    var nativeFunction1 = new NativeFunction(so_func_add1, "int", ["int", "int", "int"]);
    var nativeFunction2 = new NativeFunction(so_func_add2, "int", ["int", "int", "int"]);

    console.log("nativeFunction1 调用：", nativeFunction1(1, 2, 3));
    console.log("nativeFunction2 调用：", nativeFunction2(2, 5, 3));

}

//intercept 拦截打印 native 方法
//通过 Intercept 拦截器打印 native 方法参数和返回值, 并修改返回值
function hook06() {
//onEnter: 函数(args) : 回调函数, 给定一个参数 args, 用于读取或者写入参数作为 NativePointer 对象的指针;
    // onLeave: 函数(retval) : 回调函数给定一个参数 retval, 该参数是包含原始返回值的 NativePointer 派生对象; 可以调用 retval.replace(1234) 以整数 1234 替换返回值, 或者调用retval.replace(ptr("0x1234")) 以替换为指针;
    //注意: retval 对象会在 onLeave 调用中回收, 因此不要将其存储在回调之外使用, 如果需要存储包含的值, 需要制作深拷贝, 如 ptr(retval.toString())
    var find_func_from_exports_add_c_addr = Module.getExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    console.log("find_func_from_exports_add_c_addr = ", find_func_from_exports_add_c_addr);
    // 添加拦截器
    Interceptor.attach(find_func_from_exports_add_c_addr, {
        onEnter: function (args) {
            console.log("args[0] = ", args[0], args[0].toInt32());//args[0] =  0x7c310e0460 823002208
            console.log("args[1] = ", args[1]), args[1].toInt32();

        }, onLeave: function (retval) {
            console.log("add_c result is :", retval.toInt32());//add_c result is : 18
            // 修改返回值
            retval.replace(100)
        }
    })
}

// 通过 intercept 拦截器 替换原方法
function hook07() {
    Java.perform(function () {
        var so_func_add1 = Module.getExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
        var nativeFunction = new NativeFunction(so_func_add1, "int", ["int", "int", "int"]);
        console.log(nativeFunction(5, 6, 8));
        //这里对原函数的功能进行替换实现
        Interceptor.replace(nativeFunction, new NativeCallback(function (a, b, c) {
            //h不论是什么参数都返回123
            return 123;
        }, "int", ["int", "int", "int"]));
        //再次调用 则返回123
        console.log("result:", nativeFunction(1, 2, 9));//result: 123
    })
}

// inline hook 通俗点说, inline hook就是通过内存地址, 进行 hook;
function hook08() {
    var so_addr_data = Process.getModuleByName("libxiaojianbang.so");
    if (so_addr_data) {
        var so_addr_2868 = so_addr_data.base.add(0x2868);
        console.log("so_addr_2868 = ", so_addr_2868);//so_addr_2868 =  0x7c1ae19868
        Java.perform(function () {
            Interceptor.attach(so_addr_2868, {
                onEnter: function (args) {
                    console.log("so_addr_2868 ", this.context.x1, this.context.x2, this.context.W3, this.context.W4)
                },
                onLeave: function (retval) {
                    console.log("retval is :", retval.toInt32())

                }
            })
        })
    }
}

// so 层方法注册到 js  主动调用
/*
new NativeFunction(address, returnType, argTypes[, options])
    address : 函数地址
    returnType : 指定返回类型
    argTypes : 数组指定参数类型
    类型可选: void, pointer, int, uint, long, ulong, char, uchar, float, double, int8, uint8, int16, int32, uint32, int64, uint64; 参照函数所需的 type 来定义即可;

*/
function hook09() {
    var baseAddress = Module.getBaseAddress("libnative-lib.so");
    var addr_add = baseAddress.add(0x0000A28C);
    var nativeFunction = new NativeFunction(addr_add, "int", ["int", "int"]);
    var result = nativeFunction(1, 2);
    console.log(result);
}

function hook099() {
    Java.perform(function () {
        // 获取 so 文件基地址
        var baseAddress = Module.getBaseAddress("xxx.so");
        // 获取目标函数偏移
        sub_834_addr = baseAddress.add(0x835);
        // 使用 new NativeFunction 将函数注册到 js
        var sub_834 = new NativeFunction(sub_834_addr, 'pointer', ['pointer']);
        // 开辟内存, 创建入参
        var arg0 = Memory.alloc(10);
        ptr(arg0).writeUtf8String("123");
        var result = sub_834(arg0);
        console.log("result is :", hexdump(result));


    })
}

// hook libart 中的jni 方法
//jni 全部定在在 /system/lib(64)/libart.so 文件中, 通过枚举 symbols 筛选出指定的方法
function hook10() {
    var GetStringUTFChars_addr = null;
    //jni系统函数都在 libart.so 中
    var module_libart = Process.getModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var name = symbols[i].name;
        //过滤我们想要的那个函数
        if (name.indexOf("JNI") >= 0 && name.indexOf("art") >= 0 && name.indexOf("CheckJNI") >= -1) {
            if (name.indexOf("GetStringUTFChars") >= 0) {
                console.log(name);
                //获取到指定 jni 方法地址
                GetStringUTFChars_addr = symbols[i].address;
            }
        }
    }

    console.log("GetStringUTFChars :", GetStringUTFChars);
    Java.perform(function () {

        Interceptor.attach(GetStringUTFChars_addr, {
            onEnter: function (args) {
                // console.log("args[0] is : ", args[0]);
                // console.log("args[1] is : ", args[1]);
                console.log(" native args[1] is :", Java.vm.tryGetEnv().getStringUtfChars(args[1], null).readCString());
                Thread.backtrace(this.context, Backtracer.FUZZY)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n';

                // console.log("native args[1] is :", Java.cast(args[1], Java.use("java.lang.String")));
                // console.log("native args[1] is :", Memory.readCString(Java.vm.getEnv().getStringUtfChars(args[1],null)));
            }, onLeave: function (retval) {
                // retval const char*
                console.log("GetStringUTFChars onLeave : ", ptr(retval).readCString())
            }
        })
    })

}


// hook native 调用栈
function hook12() {
    Interceptor.attach(f, {
        onEnter: function (args) {
            console.log('RegisterNatives called from:\n' +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
        }
    });
}

// frida 文件写入 frida hook libc
function hook13() {
    var addr_fopen = Module.getExportByName("libc.so", "fopen");
    var addr_fputs = Module.getExportByName("libc.so", "fputs");
    var addr_fclose = Module.getExportByName("libc.so", "fclose");

    // 将 libc 的系统方法注册到 js 层
    var fopen = new NativeFunction(addr_fopen, "pointer", ["pointer", "pointer"]);
    var fputs = new NativeFunction(addr_fputs, "int", ["pointer", "pointer"]);
    var fclose = new NativeFunction(addr_fclose, "int", ["pointer"]);

    // 在 js 层主动调用 libc 的方法
    // 不能直接将 js 的字符串传给 libc中的方法, 需要进行转换
    var filename = Memory.allocUtf8String("/sdcard/reg.dat");
    var open_mode = Memory.allocUtf8String("w");
    var file = fopen(filename, open_mode);

    var buffer = Memory.allocUtf8String("content from frida");
    var result = fputs(buffer, file);
    console.log("fputs ret: ", result);

    // 关闭文件
    fclose(file);
}

//hook 读写std_string
function hook14() {
    //readStdString
    var str;
    var isTiny = (str.readU8 & 1) === 0;
    if (isTiny) {
        return str.add(1).readUtf8String();
    }
    return str.add(2 * Process.pointerSize).readPointer().readUtf8String();

    //writeStdString
    var isTiny = (str.readU8() & 1) === 0;
    if (isTiny) {
        str.add(1).writeUtf8String(content);
    } else {
        str.add(2 * Process.pointerSize).readPointer().writeUtf8String(content);
    }

}



function main() {
    hook08()
}

setImmediate(main)