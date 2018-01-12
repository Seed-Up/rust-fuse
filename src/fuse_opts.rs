

//
// FUSE arguments (see fuse_opt.h for details)
//

use libc::{c_char, c_int};

#[repr(C)]
#[derive(Debug)]
pub struct fuse_args {
    pub argc: c_int,
    pub argv: *const *const c_char,
    pub allocated: c_int,
}

cfg_if! {
    if #[cfg(feature="rust-mount")] {

        use libc::{mode_t, uid_t, gid_t};
        use getopts::Options;
        use std::str::FromStr;
        use std::ffi::CStr;
        use std::slice;

        #[derive(Copy, Clone, Debug, PartialEq)]
        pub struct ParseError;

        pub enum MetaFuseOpt {
            Uid(uid_t),
            Gid(gid_t),
            RootMode(mode_t),
            AllowOther,
            AutoUnmount,
            DefaultPermissions,
            NonEmpty,
            SubType(String),
            #[cfg(target_os = "darwin")]
            Volname(String), // osxfuse option
        }
        use self::MetaFuseOpt::*;

        impl FromStr for MetaFuseOpt {
            type Err = ParseError;

            fn from_str(s :&str) -> Result<Self, Self::Err> {
                let (a, b) = s.split_at(s.find("=").unwrap_or(s.len()));

                match (a, String::from(b.trim_left_matches('='))) {
                    ("user_id", val) => Ok(Uid(val.parse::<uid_t>().unwrap())),
                    ("group_id", val) => Ok(Gid(val.parse::<gid_t>().unwrap())),
                    ("rootmode", val) => Ok(RootMode(val.parse::<mode_t>().unwrap())),
                    ("allow_other", _) => Ok(AllowOther),
                    ("auto_unmount", _) => Ok(AutoUnmount),
                    ("default_permissions", _) => Ok(DefaultPermissions),
                    ("nonempty", _) => Ok(NonEmpty),
                    ("subtype", val) => Ok(SubType(val.clone())),
                    #[cfg(target_os = "darwin")]
                    ("volname", val) => Ok(Volname(val.clone())),
                    _ => Err(ParseError),
                }
            }
        }

        impl ToString for MetaFuseOpt {
            fn to_string(&self) -> String {
                match *self {
                    Uid(val) => format!("user_id={}", val),
                    Gid(val) => format!("group_id={}", val),
                    RootMode(val) => format!("rootmode={}", val),
                    AllowOther => String::from("allow_other"),
                    AutoUnmount => String::from("auto_unmount"),
                    DefaultPermissions => String::from("default_permissions"),
                    NonEmpty => String::from("nonempty"),
                    SubType(ref val) => format!("subtype={}", val),
                    #[cfg(target_os = "darwin")]
                    Volname(ref val) => format!("volname={}", val),
                }
            }
        }

        //
        // fn get_get(type: ident, tab: FuseOpts) -> Option<ident::value>
        //
        macro_rules! get_opt_fuse {
            ($type: ident, $tab: expr) => {{
                let mut res = None;
                for i in $tab.opts_fuse.iter().rev() {
                    if let MetaFuseOpt::$type(v) = *i {
                        res = Some(v);
                        break ;
                    }
                }
                res
            }}
        }
        
        macro_rules! is_opt_fusemount {
            ($type: ident, $tab: expr) => {{
                let mut res = false;
                for i in $tab.opts_fusermount.iter().rev() {
                    match i {
                        &MetaFuseOpt::$type => {res = true; break; }
                        _ => (),
                    }
                }
                res
            }}
        }

        pub struct FuseOpts {
            pub opts_fuse: Vec<MetaFuseOpt>,
            pub opts_fusermount: Vec<MetaFuseOpt>,
        }

        #[deprecated]
        impl ToString for FuseOpts {
            fn to_string(&self) -> String {
                self.opts_fuse.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",")
            }
        }

        impl FuseOpts {
            pub fn new() -> FuseOpts {
                FuseOpts {
                    opts_fuse: Vec::new(),
                    opts_fusermount: Vec::new(),
                }
            }

            pub fn add_opt(&mut self, opt: MetaFuseOpt) {
                match opt {
                    AutoUnmount => self.opts_fusermount.push(opt),
                    _ => self.opts_fuse.push(opt),
                }
            }

            pub fn fuse_opt_parse(&mut self, args: &fuse_args) {
                let mut opts = Options::new();
                opts.optmulti("o", "option", "", "FILE");

                let argv: Vec<&str> = unsafe {
                    let paths: &[*const _] = slice::from_raw_parts(args.argv, args.argc as usize);
                    paths.iter().map(
                        |cs| CStr::from_ptr(*cs).to_str().expect("Error convert argv")
                        ).collect()
                };

                let matches = opts.parse(argv.iter()).unwrap();
                let optss: _ = matches.opt_strs("o");
                let opts = optss.iter().map(|x| x.split(",").collect()).collect::<Vec<Vec<_>>>().concat();
                opts.iter().map(|x| MetaFuseOpt::from_str(x.trim()).unwrap())
                .for_each(|opt| self.add_opt(opt));
            }
        }
    }
}
