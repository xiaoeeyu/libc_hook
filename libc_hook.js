function beginAnti(){
    Java.perform(function(){
        Java.choose("com.xiaoeryu.demoso1.MainActivity",{
            onMatch: function(instance){
                console.log("found instance")
                instance.init()
            }, onComplete:function(){
                console.log("Search complete")
            }
        })
    })
}

function hook_pthread(){
    var pthread_create_addr = Module.findExportByName("libc.so", 'pthread_create')
    var time_addr = Module.findExportByName("libc.so", 'time')
    console.log("pthread_create_addr => ", pthread_create_addr)
    Interceptor.attach(pthread_create_addr, {
        onEnter: function(args){
            console.log("args => ", args[0], args[1], args[2], args[3])
            var libdemoso1_addr = Module.findBaseAddress("libdemoso1.so")
            if(libdemoso1_addr != null){
                console.log("libdemoso1_addr => ", libdemoso1_addr)
                var dete_frida_loop_addr = args[2] - libdemoso1_addr
                console.log("dete_frida_loop_offset is => ", dete_frida_loop_addr)
                if(args[2] - libdemoso1_addr == 126276){
                    args[2] = time_addr
                    console.log("end args[2] => ", args[2])
                }
            }
        }, onLeave: function(retval){
            console.log("retval => ", retval)
        }
    })
}

function replace_pthread(){
    var pthread_create_addr = Module.findExportByName("libc.so", 'pthread_create')
    console.log("pthread_create_addr => ", pthread_create_addr)
    var pthread_create = new NativeFunction(pthread_create_addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'])
    Interceptor.replace(pthread_create_addr, new NativeCallback(function(args0, args1, args2, args3){
        console.log("replace_pthread args: ", args0, args1, args2, args3)
        var libdemoso1_addr = Module.findBaseAddress("libdemoso1.so")
        if(libdemoso1_addr != null){
            console.log("libdemoso1_addr => ", libdemoso1_addr)
            if(args2 - libdemoso1_addr == 126276){
                console.log("dete_frida_loop_offset is => ", args2 - libdemoso1_addr)
                return null
            }
        }
        return pthread_create(args0, args1, args2, args3)
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']
    ))
}

function writeSomething(path, contents){
    var fopen_addr = Module.findExportByName("libc.so", 'fopen')
    var fputs_addr = Module.findExportByName("libc.so", 'fputs')
    var fclose_addr = Module.findExportByName("libc.so", 'fclose')
    // console.log("fopen_addr => ", fopen_addr, "fputs_addr => ", fputs_addr, "fclose_addr => ", fclose_addr)

    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
    var fopen = new NativeFunction(fopen_addr, 'pointer', ['pointer', 'pointer'])
    // int fputs(const char *restrict s, FILE *restrict stream);
    var fputs = new NativeFunction(fputs_addr, 'int', ['pointer', 'pointer'])
    // int fclose(FILE *stream);
    var fclose = new NativeFunction(fclose_addr, 'int', ['pointer'])

    var fileName = Memory.allocUtf8String(path)
    var mode = Memory.allocUtf8String("a+")

    var fp = fopen(fileName, mode)
    var context1 = Memory.allocUtf8String(contents)
    fputs(context1, fp)
    fclose(fp)
}

function EnumerateAllExports(){
    var modules = Process.enumerateModulesSync()
    for(var i = 0; i < modules.length; i++){
        // console.log("modules => ", JSON.stringify(modules[i]))
        var modele_name = modules[i].name
        var exports = modules[i].enumerateExports()
        console.log("exports => ", JSON.stringify(exports))
        for(var j = 0; j < exports.length; j++){
            writeSomething("/sdcard/settings/" + modele_name + ".txt", "type: " + exports[j].type + " name: " + exports[j].name + " addr: " + exports[j].address + "\n")
        }
    }
}

setImmediate(EnumerateAllExports)
