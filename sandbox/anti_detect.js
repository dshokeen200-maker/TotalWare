'use strict';

/* ============================================================================
 *  TotalWare — anti_detect.js  (UNIVERSAL v2)
 *  Maqsad: koi bhi APK emulator pe CONFIRM chale + apna asli traffic/C2 dikhaye.
 *  Categories handled:
 *   1. Emulator detection (Build/props/ABI/telephony/files/sensors/debug/monkey)
 *   2. ARM-only packers  -> ABI spoof (arm64 lib load + x86 translate)
 *   3. C2 reveal         -> DNS/Socket/HTTP/OkHttp/TLS hooks
 *   4. Browser/intent C2 -> Uri.parse / startActivity / WebView
 *   5. Dropper           -> DexClassLoader / Runtime.exec
 *   6. Headless service malware -> Foreground-Service restriction bypass (crash na ho)
 * ========================================================================== */

// ── "Asli phone" profile (Samsung Galaxy S10) ──
var REAL = {
    MODEL:"SM-G973F", MANUFACTURER:"samsung", BRAND:"samsung", DEVICE:"beyond1",
    PRODUCT:"beyond1ltexx", BOARD:"exynos9820", HARDWARE:"exynos9820",
    BOOTLOADER:"G973FXXU9EUE1", HOST:"SWHD7710", USER:"dpi",
    TAGS:"release-keys", TYPE:"user",
    FINGERPRINT:"samsung/beyond1ltexx/beyond1:11/RP1A.200720.012/G973FXXU9EUE1:user/release-keys"
};

// ── getprop ke jhoothe jawab ──
var FAKE_PROPS = {
    "ro.kernel.qemu":"0", "ro.kernel.qemu.gles":"0", "ro.hardware":"exynos9820",
    "ro.product.model":"SM-G973F", "ro.product.brand":"samsung",
    "ro.product.manufacturer":"samsung", "ro.product.device":"beyond1",
    "ro.product.name":"beyond1ltexx", "ro.product.board":"exynos9820",
    "ro.build.fingerprint":REAL.FINGERPRINT, "ro.bootloader":"G973FXXU9EUE1",
    "ro.build.tags":"release-keys", "ro.build.type":"user",
    "gsm.version.baseband":"G973FXXU9EUE1", "ro.secure":"1", "ro.debuggable":"0",
    "init.svc.qemud":"", "init.svc.qemu-props":"", "qemu.hw.mainkeys":"",
    // ABI spoof (ARM-only packers ke liye)
    "ro.product.cpu.abi":"arm64-v8a", "ro.product.cpu.abilist":"arm64-v8a,armeabi-v7a,armeabi",
    "ro.product.cpu.abilist64":"arm64-v8a", "ro.product.cpu.abilist32":"armeabi-v7a,armeabi"
};

// safe-hook helper: koi class missing ho to pura script crash na ho
function safe(label, fn){ try{ fn(); }catch(e){ console.log("[-] skip "+label+" ("+e.message+")"); } }

Java.perform(function () {
    console.log("\n[*] TotalWare anti-detect v2 LOADED — universal hooks lag rahe hain...\n");

    var Build = Java.use("android.os.Build");

    // ── PART 1: Build fields ──
    safe("Build", function(){
        Build.MODEL.value=REAL.MODEL; Build.MANUFACTURER.value=REAL.MANUFACTURER;
        Build.BRAND.value=REAL.BRAND; Build.DEVICE.value=REAL.DEVICE;
        Build.PRODUCT.value=REAL.PRODUCT; Build.BOARD.value=REAL.BOARD;
        Build.HARDWARE.value=REAL.HARDWARE; Build.BOOTLOADER.value=REAL.BOOTLOADER;
        Build.HOST.value=REAL.HOST; Build.USER.value=REAL.USER;
        Build.TAGS.value=REAL.TAGS; Build.TYPE.value=REAL.TYPE;
        Build.FINGERPRINT.value=REAL.FINGERPRINT;
        try{ Build.getSerial.implementation=function(){ return "RF8M802ABCD"; }; }catch(e){}
    });

    // ── PART 2a: ABI spoof (device ko ARM batao) ──
    safe("ABI", function(){
        Build.CPU_ABI.value="arm64-v8a"; Build.CPU_ABI2.value="armeabi-v7a";
        Build.SUPPORTED_ABIS.value=Java.array('java.lang.String',['arm64-v8a','armeabi-v7a','armeabi']);
        Build.SUPPORTED_64_BIT_ABIS.value=Java.array('java.lang.String',['arm64-v8a']);
        Build.SUPPORTED_32_BIT_ABIS.value=Java.array('java.lang.String',['armeabi-v7a','armeabi']);
    });

    // ── PART 2b: SystemProperties + System.getProperty ──
    safe("SystemProperties", function(){
        var SP=Java.use("android.os.SystemProperties");
        SP.get.overload('java.lang.String').implementation=function(k){ return FAKE_PROPS.hasOwnProperty(k)?FAKE_PROPS[k]:this.get(k); };
        SP.get.overload('java.lang.String','java.lang.String').implementation=function(k,d){ return FAKE_PROPS.hasOwnProperty(k)?FAKE_PROPS[k]:this.get(k,d); };
    });
    safe("System.getProperty", function(){
        var Sys=Java.use("java.lang.System");
        Sys.getProperty.overload('java.lang.String').implementation=function(k){ return k==="os.arch"?"aarch64":this.getProperty(k); };
    });

    // ── PART 3a: TelephonyManager ──
    safe("Telephony", function(){
        var TM=Java.use("android.telephony.TelephonyManager");
        function fk(m,v){ try{ TM[m].overloads.forEach(function(o){ o.implementation=function(){ return v; }; }); }catch(e){} }
        fk("getDeviceId","356938035643809"); fk("getImei","356938035643809"); fk("getMeid","356938035643809");
        fk("getLine1Number","+919812345678"); fk("getSimSerialNumber","8991101200003204510");
        fk("getSubscriberId","405861234567890"); fk("getNetworkOperatorName","Jio 4G");
        fk("getSimOperatorName","Jio 4G"); fk("getNetworkOperator","405861");
        fk("getSimCountryIso","in"); fk("getNetworkCountryIso","in");
    });

    // ── PART 3b: ANDROID_ID ──
    safe("ANDROID_ID", function(){
        var Sec=Java.use("android.provider.Settings$Secure");
        Sec.getString.implementation=function(cr,name){ return name==="android_id"?"a1b2c3d4e5f60718":this.getString(cr,name); };
    });

    // ── PART 3c: File.exists() — qemu fingerprint files chhupao ──
    safe("File.exists", function(){
        var QEMU=["qemu_pipe","qemud","goldfish","ranchu","libc_malloc_debug_qemu","qemu_trace",
                  "qemu-props","genyd","baseband_genyd","vbox","nox","ttVM","android_x86","/sys/qemu_trace"];
        var File=Java.use("java.io.File");
        File.exists.implementation=function(){
            var p=""; try{ p=this.getAbsolutePath(); }catch(e){}
            for(var i=0;i<QEMU.length;i++){ if(p && p.indexOf(QEMU[i])!==-1){ console.log("[evade] File.exists block: "+p); return false; } }
            return this.exists();
        };
    });

    // ── PART 3d (NAYA): anti-debug + monkey + sensor detection ──
    safe("anti-debug/monkey", function(){
        var Debug=Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation=function(){ return false; };  // analyst chhupao
        var AM=Java.use("android.app.ActivityManager");
        AM.isUserAMonkey.implementation=function(){ return false; };           // "monkey" automation chhupao
    });

    // ── PART 4: C2 REVEAL (network) ──
    safe("DNS", function(){
        var IA=Java.use("java.net.InetAddress");
        IA.getByName.implementation=function(h){ console.log("[C2] DNS getByName: "+h); return this.getByName(h); };
        IA.getAllByName.implementation=function(h){ console.log("[C2] DNS getAllByName: "+h); return this.getAllByName(h); };
    });
    safe("Socket", function(){
        var S=Java.use("java.net.Socket");
        S.connect.overload('java.net.SocketAddress','int').implementation=function(a,t){ try{ console.log("[C2] Socket connect: "+a.toString()); }catch(e){} return this.connect(a,t); };
    });
    safe("URL", function(){
        var U=Java.use("java.net.URL");
        U.openConnection.overload().implementation=function(){ try{ console.log("[C2] URL.openConnection: "+this.toString()); }catch(e){} return this.openConnection(); };
    });
    safe("OkHttp", function(){
        var R=Java.use("okhttp3.Request");
        R.url.overload().implementation=function(){ var u=this.url(); try{ console.log("[C2] OkHttp: "+u.toString()); }catch(e){} return u; };
    });
    safe("TLS", function(){
        var F=Java.use("javax.net.ssl.SSLSocketFactory");
        F.createSocket.overload('java.net.Socket','java.lang.String','int','boolean').implementation=function(s,h,p,a){ console.log("[C2] TLS createSocket: "+h+":"+p); return this.createSocket(s,h,p,a); };
    });

    // ── PART 5: Intent / URL reveal (browser/webview C2) ──
    safe("Uri.parse", function(){
        var Uri=Java.use("android.net.Uri");
        Uri.parse.overload('java.lang.String').implementation=function(s){ try{ if(s && s.toLowerCase().indexOf("http")!==-1) console.log("[URL] Uri.parse: "+s); }catch(e){} return this.parse(s); };
    });
    safe("startActivity", function(){
        var CW=Java.use("android.content.ContextWrapper");
        CW.startActivity.overloads.forEach(function(o){
            o.implementation=function(){ try{ var d=arguments[0].getDataString(); if(d) console.log("[URL] startActivity: "+d); }catch(e){} return o.apply(this,arguments); };
        });
    });
    safe("WebView", function(){
        var W=Java.use("android.webkit.WebView");
        W.loadUrl.overload('java.lang.String').implementation=function(u){ console.log("[URL] WebView.loadUrl: "+u); return this.loadUrl(u); };
    });

    // ── PART 5b: Dropper reveal ──
    safe("DexClassLoader", function(){
        var D=Java.use("dalvik.system.DexClassLoader");
        D.$init.implementation=function(a,b,c,d){ console.log("[DROP] DexClassLoader: "+a); return this.$init(a,b,c,d); };
    });
    safe("Runtime.exec", function(){
        var RT=Java.use("java.lang.Runtime");
        RT.exec.overload('java.lang.String').implementation=function(c){ console.log("[DROP] Runtime.exec: "+c); return this.exec(c); };
    });

    // ── PART 6 (NAYA): Foreground-Service restriction bypass ──
    //  Headless malware (jaise woh "Sexy 1V1" payload) background se foreground-service
    //  start karta hai -> Android 12+ use rokta hai -> app crash. Hum crash rok dete hai
    //  taaki app zinda rahe aur apna asli kaam (C2) kar sake.
    safe("FGS-bypass", function(){
        var CW=Java.use("android.content.ContextWrapper");
        CW.startForegroundService.implementation=function(intent){
            try{ console.log("[run] startForegroundService -> startService (FGS bypass): "+intent.getComponent()); }catch(e){}
            try{ return this.startService(intent); }           // pehle normal service try
            catch(e1){
                try{ return this.startForegroundService(intent); } // phir original try
                catch(e2){ console.log("[run] FGS blocked — crash swallow kiya (app zinda)"); return null; }
            }
        };
    });

    // ── verify ──
    safe("verify", function(){
        var SP=Java.use("android.os.SystemProperties");
        var Sys=Java.use("java.lang.System");
        console.log("[verify] MODEL          = "+Build.MODEL.value);
        console.log("[verify] ro.kernel.qemu = "+SP.get("ro.kernel.qemu")+"   (ab '0')");
        console.log("[verify] os.arch        = "+Sys.getProperty("os.arch"));
        console.log("[verify] primary ABI    = "+Build.SUPPORTED_ABIS.value[0]);
        console.log("");
    });

    console.log("[*] Sab hooks active. App ab REAL phone dekh raha hai.\n");
});
