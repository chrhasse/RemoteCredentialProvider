use windows::{core::{Result, PWSTR, PCWSTR}, w};
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
        let password = PCWSTR(std::ptr::null());
        let e = Rswstr::clone_from_str("")?; // TileImage
        println!("{e}");
        let b = e.clone();
        println!("b:{b}");
        let e = Rswstr::clone_from_str("Auto Login")?; // Label
        println!("{e}");
        let e = Rswstr::clone_from_str("Auto Login")?; // LargeText
        println!("{e}");
        //let e = Rswstr::clone_from_pcwstr(password)?; // Password
        println!("{e}");
        let e = Rswstr::clone_from_str("Submit")?; // SubmitButton
        println!("{e}");
    }
    Ok(())
}