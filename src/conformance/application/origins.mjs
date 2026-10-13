const origins=new WeakMap();
export function markAdapter(adapter,origin){origins.set(adapter,Object.freeze(origin));return Object.freeze(adapter);}
export function adapterOrigin(adapter){return origins.get(adapter)??{source:'declaration',id:'unregistered-adapter',mode:null};}
