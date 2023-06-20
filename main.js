Java.perform(function () {
  const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
  const AGENT_PATH = "/data/local/tmp/agent.dex";
  const AGENT_CLASS = "Agent";
  const AGENT_FUNCTION = "log_called_function";
  const STRING_CLASS = Java.use("java.lang.String").class;
  const AGENT_FUNCTION_ARGUMENTS = [STRING_CLASS, STRING_CLASS, STRING_CLASS];
  const AGENT_LIBRARY = "libagent.so";
  const AGENT_FUNCTION_NATIVE = "_Z6reportPv"; // mangled name of void report(void *address_of_crash) function
  const System = Java.use("java.lang.System");
  const Runtime = Java.use("java.lang.Runtime");
  const SystemLoadLibrary = System.loadLibrary.overload("java.lang.String");
  const VMStack = Java.use("dalvik.system.VMStack");

  var LOADED_AGENT_CLASS = null;
  let DICTIONARY_CLASS_OF_METHODS = {};
  let all_methods = [];
  let agentLoaded = false;
  let ExecutableMemoryBlacklist = [];

  const PROT_EXEC = 0x4;

  // We hook system load library to intercept loading any native library
  // After loading we intercept AGENT_NATIVE_FUNCTION
  // We do this because we have to normally wait until our AGENT_LIBRARY to be loaded
  // But in our "run.py" we add our AGENT_LIBRARY as dependency to all existing libraries
  // So, when a library loaded eour AGENT_LIBRARY will be loaded as well, then now we can replace our AGENT_NATIVE_FUNCTION function
  SystemLoadLibrary.implementation = function (library) {
    console.log("Loading dynamic library => " + library);
    try {
      const loaded = Runtime.getRuntime().loadLibrary0(
        VMStack.getCallingClassLoader(),
        library
      );
      const AGENT_NATIVE_FUNCTION_HANDLE = Module.findExportByName(
        AGENT_LIBRARY,
        AGENT_FUNCTION_NATIVE
      );

      if (AGENT_NATIVE_FUNCTION_HANDLE == null) {
        return loaded;
      }
      console.log("Agent function handle -> ", AGENT_NATIVE_FUNCTION_HANDLE);
      Interceptor.replace(
        AGENT_NATIVE_FUNCTION_HANDLE,
        new NativeCallback(
          function (crash_address) {
            console.log("Crash address -> ", crash_address);
            for (var i = 0; i < ExecutableMemoryBlacklist.length; i++) {
              console.log(
                "comparing with -> ",
                ExecutableMemoryBlacklist[i].name,
                "addr",
                ExecutableMemoryBlacklist[i].addr.toString(16),
                "length",
                ExecutableMemoryBlacklist[i].length
              );

              if (
                crash_address.compare(
                  ExecutableMemoryBlacklist[i].addr,
                  ExecutableMemoryBlacklist[i] +
                    ExecutableMemoryBlacklist[i].length
                ) == 0
              ) {
                console.log(
                  "Crash address allocation with -> ",
                  ExecutableMemoryBlacklist[i].name,
                  "addr",
                  ExecutableMemoryBlacklist[i].addr.toString(16),
                  "length",
                  ExecutableMemoryBlacklist[i].length
                );
                // dump memory at max 100 byte
                var buf = Memory.readByteArray(
                  ExecutableMemoryBlacklist[i].addr,
                  Math.min(100, ExecutableMemoryBlacklist[i].length)
                );

                console.log(
                  hexdump(buf, {
                    offset: 0,
                    length: 100,
                    header: true,
                    ansi: true,
                  })
                );
                // Sleep for 5 seconds
                Java.use("java.lang.Thread").sleep(5000);
                break;
              }
            }
          },
          "void",
          ["pointer"]
        )
      );
      return loaded;
    } catch (ex) {
      console.log(ex);
    }
  };

  // -------------------------------------- JAVA PART --------------------------------------

  // get caller from stacktrace
  function get_caller() {
    var straces = Java.use("java.lang.Exception")
      .$new("Exception")
      .getStackTrace();
    var caller = straces[3].getClassName() + "." + straces[3].getMethodName();
    return caller;
  }

  // make toast function
  function makeToast(message) {
    Java.scheduleOnMainThread(function () {
      const Toast = Java.use("android.widget.Toast");
      var currentApplication = Java.use(
        "android.app.ActivityThread"
      ).currentApplication();
      var context = currentApplication.getApplicationContext();
      Toast.makeText(
        context,
        Java.use("java.lang.String").$new(message),
        Toast.LENGTH_SHORT.value
      ).show();
    });
  }

  // call agent function from our agent dex file
  function callAgentFunction(function_name, class_name, caller) {
    const method = LOADED_AGENT_CLASS.getMethod(
      AGENT_FUNCTION,
      AGENT_FUNCTION_ARGUMENTS
    );
    return method.invoke(null, [
      Java.use("java.lang.String").$new(function_name),
      Java.use("java.lang.String").$new(class_name),
      Java.use("java.lang.String").$new(caller),
    ]);
  }

  // load agent dex file
  function loadAgent() {
    Java.perform(function () {
      var context = Java.use("android.app.ActivityThread")
        .currentApplication()
        .getApplicationContext();
      var dexOptimizedPath = "/data/local/tmp";
      var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
      var classLoader = DexClassLoader.$new(
        AGENT_PATH,
        dexOptimizedPath,
        null,
        context.getClassLoader()
      );
      // load agent class
      LOADED_AGENT_CLASS = Java.cast(
        classLoader.loadClass(AGENT_CLASS),
        Java.use("java.lang.Class")
      );
    });
  }

  // hook DexClassLoader constructor
  DexClassLoader.$init.overload(
    "java.lang.String",
    "java.lang.String",
    "java.lang.String",
    "java.lang.ClassLoader"
  ).implementation = function (
    dexPath,
    optimizedDirectory,
    librarySearchPath,
    parent
  ) {
    console.log("DexClassLoader -> ", dexPath, "caller -> ", get_caller());
    this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);

    if (!agentLoaded) {
      agentLoaded = true;
      loadAgent();
      console.log("Agent loaded");
    }

    var loadedDex = Java.use("dalvik.system.DexFile").$new(dexPath);
    var dexEntries = loadedDex.entries();
    var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    var File = Java.use("java.io.File");
    var systemClassLoader = Java.classFactory.loader;
    var loader = BaseDexClassLoader.$new(
      dexPath,
      File.$new("/data/local/tmp"),
      null,
      systemClassLoader
    );

    while (dexEntries.hasMoreElements()) {
      var className = dexEntries.nextElement().toString();
      className = className.replace(/\//g, "."); // replace slashes with dots
      try {
        var classInstance = Java.cast(
          loader.findClass(className),
          Java.use("java.lang.Class")
        );
        var methods = classInstance.getDeclaredMethods();
        console.log("[+] Class: " + className);
        DICTIONARY_CLASS_OF_METHODS[className] = [];
        methods.forEach(function (method) {
          console.log("    " + method.getName());
          DICTIONARY_CLASS_OF_METHODS[className].push(method.getName());
          all_methods.push(method.getName());
        });
      } catch (err) {
        console.log(
          "[-] An exception occurred when trying to find class " +
            className +
            " : " +
            err.message
        );
      }
    }
  };

  // hook reflected invoke method
  const Method = Java.use("java.lang.reflect.Method");
  Method.invoke.overload(
    "java.lang.Object",
    "[Ljava.lang.Object;"
  ).implementation = function (obj, args) {
    const name = this.getName();
    const class_name = this.getDeclaringClass().getName();
    if (
      DICTIONARY_CLASS_OF_METHODS[class_name] != undefined &&
      DICTIONARY_CLASS_OF_METHODS[class_name].indexOf(name) != -1
    ) {
      const message =
        "Malicious call -> " +
        class_name +
        "->" +
        name +
        " caller -> " +
        get_caller();
      console.log(message);
      makeToast(message);
      const should_continue = callAgentFunction(name, class_name, get_caller());
      if (should_continue.toString() === "false") {
        console.log("[-] Stopping execution");
        return;
      }
    }
    return this.invoke(obj, args);
  };
  // -------------------------------------- NATIVE PART --------------------------------------
  function isExecutable(protection) {
    return (protection & PROT_EXEC) === PROT_EXEC;
  }

  // hook mmap, mmap64 and mprotect to keep track of executable memory blocks
  Interceptor.attach(Module.findExportByName(null, "mmap"), {
    onEnter: function (args) {
      this.addr = ptr(args[0]);
      this.length = ptr(args[1]);
      this.protection = ptr(args[2]);
      this.executable = isExecutable(this.protection);
      // remove PROT_EXEC from protection
      args[2] = ptr(this.protection & ~PROT_EXEC);
    },
    onLeave: function (retval) {
      // if executable push to memoryBlocks
      if (retval.toInt32() != -1 && this.executable) {
        ExecutableMemoryBlacklist.push({
          addr: ptr(retval),
          length: this.length,
          protection: this.protection,
          name: "mmap",
        });
        console.log(
          "mmap(",
          retval,
          ",",
          this.length,
          ",",
          this.protection,
          ") = ",
          retval
        );
      }
    },
  });
  Interceptor.attach(Module.findExportByName(null, "mmap64"), {
    onEnter: function (args) {
      this.addr = ptr(args[0]);
      this.length = ptr(args[1]);
      this.protection = ptr(args[2]);
      this.executable = isExecutable(this.protection);
      // remove PROT_EXEC from protection
      args[2] = ptr(this.protection & ~PROT_EXEC);
    },
    onLeave: function (retval) {
      // if executable push to memoryBlocks
      if (retval.toInt32() != -1 && this.executable) {
        ExecutableMemoryBlacklist.push({
          addr: retval,
          length: this.length,
          protection: this.protection,
          name: "mmap64",
        });
        console.log(
          "mmap64(",
          retval,
          ",",
          this.length,
          ",",
          this.protection,
          ") = ",
          retval
        );
      }
    },
  });
  Interceptor.attach(Module.findExportByName(null, "mprotect"), {
    onEnter: function (args) {
      this.addr = ptr(args[0]);
      this.length = ptr(args[1]);
      this.protection = ptr(args[2]);
      this.executable = isExecutable(this.protection);
      if (this.executable) {
        args[2] = ptr(this.protection & ~PROT_EXEC);
        ExecutableMemoryBlacklist.push({
          addr: this.addr,
          length: this.length,
          protection: this.protection,
          name: "mprotect",
        });
        console.log(
          "mprotect(",
          this.addr,
          ",",
          this.length,
          ",",
          this.protection,
          ")"
        );
      }
    },
  });
});
