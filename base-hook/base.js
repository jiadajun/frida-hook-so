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
                    console.log("so_addr_2868 ", this.context.x1,this.context.x2, this.context.W3, this.context.W4)
                },
                onLeave: function (retval) {
                    console.log("retval is :", retval.toInt32())

                }
            })
        })
    }
}

// so 层方法注册到 js  主动调用
function hook09() {

}

// hook libart 中的jni 方法
function hook10() {

}

// hook libc 中的系统方法
function hook11() {

}

// hook native 调用栈
function hook12() {

}

// frida 文件写入 frida hook libc
function hook13() {

}

//hook 读写std_string
function hook14() {

}

// 针对 so 文件加载后马上 hook
function hook15() {

}

// hook libc kill
function hook16() {

}

// hook so readPointer
function hook17() {

}

// hook so waiterPointer
function hook18() {

}

// hook so readS32 readU32
function hook19() {

}

// hook so readByteArray WriterByteArray
function hook20() {

}

// hook so readCString  writerUTF8String
function hook21() {

}

// hook 获取 jni array
function hook22() {

}

// frida dump 内存中的so文件
function hook23() {

}

// hook system properties get
function hook24() {

}

// process 对象 API
function hook25() {

}

// 39 hook fgets 让 TracerPid 为 0
function hook26() {

}

// 40 frida 批量 trace
function hook27() {

}


function main() {
    hook08()
}

setImmediate(main)