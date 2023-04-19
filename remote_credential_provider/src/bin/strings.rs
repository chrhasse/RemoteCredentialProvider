use windows::{core::{Result, PWSTR}, w};
use helpers::*;
fn main() -> Result<()> {
    unsafe {
        let str1 = Rswstr::clone_from_pcwstr(w!("d̶͖̈́̇̆a̸͖̯̩̞̓̏̐̈́̀̑͗̀͜͜͝"))?;
        println!("{:?}", str1.as_wide_with_terminator());
        let str2 = Rswstr::clone_from_str("d̶͖̈́̇̆a̸͖̯̩̞̓̏̐̈́̀̑͗̀͜͜͝")?;
        println!("{:?}", str2.as_wide_with_terminator());
        println!("{:?}", str2);
        println!("{}", str2);
        println!("{:?}", Rswstr::from(PWSTR(std::ptr::null_mut() as *mut u16)));
        println!("{}", Rswstr::from(PWSTR(std::ptr::null_mut() as *mut u16)));
        let split = split_domain_and_username(&Rswstr::clone_from_str("domain\\user")?)?;
        println!("{} {}", split.domain, split.username);
    }
    Ok(())
}