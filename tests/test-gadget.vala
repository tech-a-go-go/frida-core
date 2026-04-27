namespace Sunday.GadgetTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Gadget/Standalone/load-script", Standalone.load_script);
	}

	namespace Standalone {
		private static void load_script () {
			string gadget_dir;
			string data_dir;
			switch (Sunday.Test.os ()) {
				case Sunday.Test.OS.MACOS: {
					var tests_dir = Path.get_dirname (Sunday.Test.Process.current.filename);
					var build_dir = Path.get_dirname (tests_dir);
					var source_dir = Path.get_dirname (build_dir);
					gadget_dir = Path.build_filename (build_dir, "lib", "gadget");
					data_dir = Path.build_filename (source_dir, "tests");
					break;
				}
				case Sunday.Test.OS.IOS:
				case Sunday.Test.OS.TVOS: {
					var deployment_dir = Path.get_dirname (Sunday.Test.Process.current.filename);
					gadget_dir = deployment_dir;
					data_dir = deployment_dir;
					break;
				}
				default:
					stdout.printf ("<skipping, test only available on i/macOS for now> ");
					return;
			}

			var gadget_filename = Path.build_filename (gadget_dir, "frida-gadget" + Sunday.Test.os_library_suffix ());
			var config_filename = Path.build_filename (gadget_dir, "frida-gadget.config");
			var script_filename = Path.build_filename (data_dir, "test-gadget-standalone.js");

			var envp = new string[] {
				"DYLD_INSERT_LIBRARIES=" + gadget_filename,
			};

			try {
				FileUtils.set_contents (config_filename, """{
						"interaction": {
							"type": "script",
							"path": "%s"
						}
					}""".printf (script_filename));

				var process = Sunday.Test.Process.start (Sunday.Test.Labrats.path_to_executable ("sleeper"), null, envp);
				var exitcode = process.join (5000);
				assert_true (exitcode == 123);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}
	}
}
