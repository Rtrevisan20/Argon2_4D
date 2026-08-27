unit HDArgon24D;

interface

{$IF Defined(MSWINDOWS)}
const
  ARGON2_API_LIB = 'libargon2.dll';
{$ELSEIF Defined(LINUX) or Defined(ANDROID)}
const
  ARGON2_API_LIB = 'libargon2.so';
{$ELSEIF Defined(MACOS) or Defined(IOS)}
const
  ARGON2_API_LIB = 'libargon2.dylib';
{$ELSE}
const
  ARGON2_API_LIB = 'libargon2.so';
{$ENDIF}

type
  size_t = NativeUInt;

  TArgon2 = class
  private
    class var FIterations: integer;
    class var FMemory: integer;
    class var FParallelism: integer;
    class function GenerateSalt(Size: Integer): AnsiString;
    class function ErrorMessage(const aCode: integer): string;
  public
    class function GenerateHash(const aPass: string): string;
    class function VerifyPassword(const aHash, aPass: string): boolean;
    class function IdHashEncoded(const aPass: string): string;
    class function HashEncodedVerify(const aHash, aPass: string): boolean;

    class property Iterations: integer read FIterations write FIterations;
    class property Memory: integer read FMemory write FMemory;
    class property Parallelism: integer read FParallelism write FParallelism;
  end;

function argon2_hash(
    t_cost: Cardinal; // ITERATIONS
    m_cost: Cardinal; // MEMORY
    parallelism: Cardinal; // PARALLELISM
    pwd: PAnsiChar; // PAnsiChar(Password)
    pwdlen: NativeUInt; // length password
    salt: PAnsiChar; // PAnsiChar(Salt)
    saltlen: NativeUInt; // length Salt
    hash: Pointer; // pode passar nil
    hashlen: NativeUInt; // length do hash
    encoded: PAnsiChar; // array[0..255] of AnsiChar
    encodedlen: NativeUInt; // length do encod
    argon2_type: integer; // Argon2 id = 2
    version: Cardinal // Argon2 Version = $13
): integer;

function argon2_verify(
    encoded: PAnsiChar; // Hash gerado
    pwd: Pointer; // password
    pwdlen: size_t; // length password
    Argon2Type: integer // Argon2 id = 2
): integer;

function argon2id_hash_encoded(
    t_cost: Cardinal; // ITERATIONS
    m_cost: Cardinal; // MEMORY
    parallelism: Cardinal; // PARALLELISM
    pwd: Pointer; // PAnsiChar(Password)
    pwdlen: size_t; // length password
    salt: Pointer; // PAnsiChar(Salt)
    saltlen: size_t; // length Salt
    hashlen: size_t; // length do hash
    encoded: PAnsiChar; // array[0..255] of AnsiChar
    encodedlen: size_t // length do encod
): integer;

function argon2id_verify(
    encoded: PAnsiChar; // Hash gerado
    pwd: Pointer; // password
    pwdlen: size_t // length password
): integer;

function argon2_encodedlen(
    t_cost: Cardinal; // ITERATIONS
    m_cost: Cardinal; // MEMORY
    parallelism: Cardinal; // PARALLELISM
    saltlen: Cardinal; // length Salt
    hashlen: Cardinal; // length do hash
    Argon2Type: integer // Argon2 id = 2
): size_t;

function argon2_error_message(
    error_code: integer // Code error
): PAnsiChar;

const
  SALT_LEN        = 16;  //Tamanho do Salt Aleatorio
  HASH_LEN        = 32;  //Tamanho do Hash Gerado
  ARGON2_VERSION  = $13; //Varsao do Argon2
  ARGON2_d        = 0;   //Tipo do Argon2
  ARGON2_i        = 1;   //Tipo do Argon2
  ARGON2_id       = 2;   //Tipo do Argon2

implementation

uses
  System.SysUtils
{$IF Defined(MSWINDOWS)}
  ,Winapi.Windows
{$ENDIF}
  ;

type
  TArgon2HashProc = function(
      t_cost: Cardinal;
      m_cost: Cardinal;
      parallelism: Cardinal;
      pwd: PAnsiChar;
      pwdlen: NativeUInt;
      salt: PAnsiChar;
      saltlen: NativeUInt;
      hash: Pointer;
      hashlen: NativeUInt;
      encoded: PAnsiChar;
      encodedlen: NativeUInt;
      argon2_type: integer;
      version: Cardinal
  ): integer; {$IF Defined(MSWINDOWS)} stdcall {$ELSE} cdecl {$ENDIF};

  TArgon2VerifyProc = function(
      encoded: PAnsiChar;
      pwd: Pointer;
      pwdlen: size_t;
      Argon2Type: integer
  ): integer; {$IF Defined(MSWINDOWS)} stdcall {$ELSE} cdecl {$ENDIF};

  TArgon2idHashEncodedProc = function(
      t_cost: Cardinal;
      m_cost: Cardinal;
      parallelism: Cardinal;
      pwd: Pointer;
      pwdlen: size_t;
      salt: Pointer;
      saltlen: size_t;
      hashlen: size_t;
      encoded: PAnsiChar;
      encodedlen: size_t
  ): integer; {$IF Defined(MSWINDOWS)} stdcall {$ELSE} cdecl {$ENDIF};

  TArgon2idVerifyProc = function(
      encoded: PAnsiChar;
      pwd: Pointer;
      pwdlen: size_t
  ): integer; {$IF Defined(MSWINDOWS)} stdcall {$ELSE} cdecl {$ENDIF};

  TArgon2EncodedLenProc = function(
      t_cost: Cardinal;
      m_cost: Cardinal;
      parallelism: Cardinal;
      saltlen: Cardinal;
      hashlen: Cardinal;
      Argon2Type: integer
  ): size_t; {$IF Defined(MSWINDOWS)} stdcall {$ELSE} cdecl {$ENDIF};

  TArgon2ErrorMessageProc = function(
      error_code: integer
  ): PAnsiChar; {$IF Defined(MSWINDOWS)} stdcall {$ELSE} cdecl {$ENDIF};

var
  FArgon2Handle: HMODULE;
  FArgon2Loaded: Boolean;
  FArgon2Lock: TObject;

  argon2_hash_proc: TArgon2HashProc;
  argon2_verify_proc: TArgon2VerifyProc;
  argon2id_hash_encoded_proc: TArgon2idHashEncodedProc;
  argon2id_verify_proc: TArgon2idVerifyProc;
  argon2_encodedlen_proc: TArgon2EncodedLenProc;
  argon2_error_message_proc: TArgon2ErrorMessageProc;

function LoadArgon2Library: Boolean;
begin
  if FArgon2Loaded then
    Exit(True);

  TMonitor.Enter(FArgon2Lock);
  try
    if FArgon2Loaded then
    begin
      Result := True;
      Exit;
    end;

    FArgon2Handle := SafeLoadLibrary(ARGON2_API_LIB);
    if FArgon2Handle = 0 then
      raise Exception.Create('Nao foi possivel carregar a biblioteca ' + ARGON2_API_LIB);

    @argon2_hash_proc := GetProcAddress(FArgon2Handle, 'argon2_hash');
    @argon2_verify_proc := GetProcAddress(FArgon2Handle, 'argon2_verify');
    @argon2id_hash_encoded_proc := GetProcAddress(FArgon2Handle, 'argon2id_hash_encoded');
    @argon2id_verify_proc := GetProcAddress(FArgon2Handle, 'argon2id_verify');
    @argon2_encodedlen_proc := GetProcAddress(FArgon2Handle, 'argon2_encodedlen');
    @argon2_error_message_proc := GetProcAddress(FArgon2Handle, 'argon2_error_message');

    if (not Assigned(argon2_hash_proc)) or (not Assigned(argon2_verify_proc))
      or (not Assigned(argon2id_hash_encoded_proc)) or (not Assigned(argon2id_verify_proc))
      or (not Assigned(argon2_encodedlen_proc)) or (not Assigned(argon2_error_message_proc)) then
      raise Exception.Create('A biblioteca ' + ARGON2_API_LIB
        + ' não contém todas as funçõs esperadas.');

    FArgon2Loaded := True;
    Result := True;
  finally
    TMonitor.Exit(FArgon2Lock);
  end;
end;

function argon2_hash(
    t_cost: Cardinal;
    m_cost: Cardinal;
    parallelism: Cardinal;
    pwd: PAnsiChar;
    pwdlen: NativeUInt;
    salt: PAnsiChar;
    saltlen: NativeUInt;
    hash: Pointer;
    hashlen: NativeUInt;
    encoded: PAnsiChar;
    encodedlen: NativeUInt;
    argon2_type: integer;
    version: Cardinal
): integer;
begin
  LoadArgon2Library;
  Result := argon2_hash_proc(
    t_cost,
    m_cost,
    parallelism,
    pwd,
    pwdlen,
    salt,
    saltlen,
    hash,
    hashlen,
    encoded,
    encodedlen,
    argon2_type,
    version
  );
end;

function argon2_verify(
    encoded: PAnsiChar;
    pwd: Pointer;
    pwdlen: size_t;
    Argon2Type: integer
): integer;
begin
  LoadArgon2Library;
  Result := argon2_verify_proc(encoded, pwd, pwdlen, Argon2Type);
end;

function argon2id_hash_encoded(
    t_cost: Cardinal;
    m_cost: Cardinal;
    parallelism: Cardinal;
    pwd: Pointer;
    pwdlen: size_t;
    salt: Pointer;
    saltlen: size_t;
    hashlen: size_t;
    encoded: PAnsiChar;
    encodedlen: size_t
): integer;
begin
  LoadArgon2Library;
  Result := argon2id_hash_encoded_proc(
    t_cost,
    m_cost,
    parallelism,
    pwd,
    pwdlen,
    salt,
    saltlen,
    hashlen,
    encoded,
    encodedlen
  );
end;

function argon2id_verify(
    encoded: PAnsiChar;
    pwd: Pointer;
    pwdlen: size_t
): integer;
begin
  LoadArgon2Library;
  Result := argon2id_verify_proc(encoded, pwd, pwdlen);
end;

function argon2_encodedlen(
    t_cost: Cardinal;
    m_cost: Cardinal;
    parallelism: Cardinal;
    saltlen: Cardinal;
    hashlen: Cardinal;
    Argon2Type: integer
): size_t;
begin
  LoadArgon2Library;
  Result := argon2_encodedlen_proc(t_cost, m_cost, parallelism, saltlen, hashlen, Argon2Type);
end;

function argon2_error_message(
    error_code: integer
): PAnsiChar;
begin
  LoadArgon2Library;
  Result := argon2_error_message_proc(error_code);
end;

class function TArgon2.ErrorMessage(const aCode: integer): string;
begin
  Result := string(argon2_error_message(aCode));
end;

class function TArgon2.GenerateHash(const aPass: string): string;
var
  Salt: AnsiString;
  Encoded: array[0..255] of AnsiChar;
  Res: Integer;
begin
  Salt := GenerateSalt(SALT_LEN);

  Res := argon2_hash(
    FIterations,
    FMemory,
    FParallelism,
    PAnsiChar(AnsiString(aPass)),
    Length(aPass),
    PAnsiChar(Salt),
    SALT_LEN,
    nil,
    HASH_LEN,
    @Encoded[0],
    SizeOf(Encoded),
    ARGON2_id,
    ARGON2_VERSION
  );

  if Res <> 0 then
    raise Exception.Create(ErrorMessage(Res));

  Result := string(AnsiString(Encoded));
end;

class function TArgon2.GenerateSalt(Size: Integer): AnsiString;
var
  I: Integer;
begin
  SetLength(Result, Size);
  for I := 1 to Size do
    Result[I] := AnsiChar(Random(256));
end;

class function TArgon2.IdHashEncoded(const aPass: string): string;
var
  Salt: AnsiString;
  Encoded: array[0..255] of AnsiChar;
  Res: Integer;
begin
  Salt := GenerateSalt(SALT_LEN);

  Res := argon2id_hash_encoded(
    FIterations,
    FMemory,
    FParallelism,
    PAnsiChar(AnsiString(aPass)),
    Length(aPass),
    PAnsiChar(Salt),
    SALT_LEN,
    HASH_LEN,
    @Encoded[0],
    SizeOf(Encoded)
  );

  if Res <> 0 then
    raise Exception.Create(ErrorMessage(Res));

  Result := string(AnsiString(Encoded));
end;

class function TArgon2.HashEncodedVerify(const aHash, aPass: string): boolean;
begin
  Result :=
    argon2id_verify(
      PAnsiChar(AnsiString(aHash)),
      PAnsiChar(AnsiString(aPass)),
      Length(aPass)) = 0;
end;

class function TArgon2.VerifyPassword(const aHash, aPass: string): boolean;
begin
  Result :=
    argon2_verify(
      PAnsiChar(AnsiString(aHash)),
      PAnsiChar(AnsiString(aPass)),
      Length(aPass),
      ARGON2_id) = 0;
end;

initialization
  FArgon2Lock := TObject.Create;

finalization
  if FArgon2Handle <> 0 then
    FreeLibrary(FArgon2Handle);
  FArgon2Lock.Free;

end.