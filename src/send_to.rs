use std::env;
use std::path::PathBuf;
use std::io::{BufReader,BufWriter,stdout,Write};
use std::fs::{File,remove_file};
use std::process;
use inquire::{Password,PasswordDisplayMode,Select,validator::Validation};
use magic_crypt::{new_magic_crypt,MagicCryptTrait,MagicCryptError};
use file_shred;

fn encrypt_file(pw: &str,file: &PathBuf) -> Result<(), MagicCryptError> {
    let mc = new_magic_crypt!(pw,256);

    let out_file_name = PathBuf::from(format!("{}.cry",&file.to_str().unwrap()));
    if out_file_name.exists() {
        println!("Arquivo {} já existe !",out_file_name.file_name().unwrap().to_string_lossy());
        process::exit(1)
    }
    let out_file = File::create(out_file_name).unwrap();

    let in_file = File::open(&file).unwrap();
    
    let mut in_reader = BufReader::new(in_file);
    let mut out_writer = BufWriter::new(out_file);

    mc.encrypt_reader_to_writer(&mut in_reader,&mut out_writer)
}

fn decrypt_file(pw: &str,file: &PathBuf) -> Result<(), MagicCryptError> {
    let mc = new_magic_crypt!(pw,256);

    let out_file_name = PathBuf::from(&file.parent().unwrap()).join(format!("{}",&file.file_stem().unwrap().to_str().unwrap()));
    if out_file_name.exists() {
        println!("Arquivo {} já existe !",out_file_name.file_name().unwrap().to_string_lossy());
        process::exit(1)
    }
    let out_file = File::create(out_file_name).unwrap();

    let in_file = File::open(&file).unwrap();
    
    let mut in_reader = BufReader::new(in_file);
    let mut out_writer = BufWriter::new(out_file);

    mc.decrypt_reader_to_writer(&mut in_reader,&mut out_writer)
}

fn shred_file(path: &PathBuf, delete: bool) {
    let config = file_shred::ShredConfig::non_interactive(
        vec![path],
        file_shred::Verbosity::Quiet,
        !delete,
        1,
        0,
    );
    file_shred::shred(&config).unwrap();
}

fn main() {
    //feito para ser usado no enviar para do windows
    let args = env::args();
    if args.len() < 2 {
        println!("Nenhum arquivo foi especificado.");
        process::exit(1)
    }
    let args_list: Vec<String> = args.collect();
    let file_list: Vec<PathBuf> = args_list[1..args_list.len()].iter().map(|f|PathBuf::from(f)).collect();

    let opts = vec!["Encriptar","Decriptar"];
    let sel = Select::new("Selecione uma opção:",opts.clone()).with_help_message("↑↓ para mover, enter para selecionar").prompt().expect("Erro ao ler seleção");

    let pw1 = Password::new("Digite a senha: ").with_display_mode(PasswordDisplayMode::Masked).prompt().expect("Falha ao ler senha");
    
    if sel == opts[0] {
        let validator = move |input: &str| if input != pw1 {
            Ok(Validation::Invalid("As senhas tem que combinar".into()))

        }else {
            Ok(Validation::Valid)
        };
        let pw2 = Password::new("Repita a senha").with_validator(validator).with_display_mode(PasswordDisplayMode::Masked).prompt().expect("Falha ao ler senha");
        for file in file_list {
            if !file.is_file() {
                continue;
            }else if file.to_string_lossy().ends_with("cry") {
                continue;
            }
            print!("Encriptando: {}",file.file_name().unwrap().to_string_lossy());
            stdout().flush().unwrap();
            encrypt_file(&pw2, &file).expect("Erro ao encriptar");
            print!("\rShredding: {}  ",file.file_name().unwrap().to_string_lossy());
            stdout().flush().unwrap();
            shred_file(&file, true);
            println!("\rCompleto: {}   ",file.file_name().unwrap().to_string_lossy());
        }  
    }
    else if sel == opts[1] {
        for file in file_list {
            if !file.is_file() {
                continue;
            }else if file.extension().unwrap() != "cry" {
                continue;
            }
            print!("Decriptando: {}",file.file_name().unwrap().to_string_lossy());
            stdout().flush().unwrap();
            match decrypt_file(&pw1, &file) {
                Ok(_) => {
                    remove_file(&file).expect("Falha ao apagar arquivo")
                },
                Err(_) => {
                    println!("\nSenha errada !");
                    process::exit(1)
                }
            }
            println!("\rCompleto: {}   ",file.file_name().unwrap().to_string_lossy());
        }
    }
}
