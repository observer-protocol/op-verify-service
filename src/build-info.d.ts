// Injected by tsup at build time — see tsup.config.ts. Declared here so tsc and the editor agree
// with the bundler about what exists.
//
// EVERY ONE CAN BE THE STRING "unknown". That is deliberate: a build outside a git checkout, or one
// where the engine cannot be read, must produce an artifact that SAYS it does not know rather than
// one that omits the field and reads as unstamped-but-fine.
declare const __BUILD_COMMIT__: string;
declare const __BUILD_BRANCH__: string;
/** 'clean' | 'dirty' | 'unknown'. Three-valued because a clean tree and an absent git are
 * different facts, and collapsing them stamped every build dirty. */
declare const __BUILD_DIRTY__: string;
declare const __BUILT_AT__: string;
declare const __BUILD_ENGINE__: string;
