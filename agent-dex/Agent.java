public class Agent {
    // This class will be inject to target app

    // if you change this function name or signature change it from main.js, too
    // (AGENT_FUNCTION -> log_called_function)
    public static boolean log_called_function(String fuction_name, String class_name, String caller) {
        System.out.println("Function: " + fuction_name + " in class: " + class_name + " called by: " + caller);
        // this return value decides if the malicios function should be executed or not
        // as an example, we can make if function_name is equal to test_function return
        // true, and if this function is called it will not crash instead it will
        // execute it
        return true;
    }
}
