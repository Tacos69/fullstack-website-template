import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsJWT } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  @ApiProperty()
  email: string;

  @ApiProperty()
  password: string;

  @ApiProperty()
  confirmPassword: string;

  @ApiProperty()
  name?: string;
}

export class LoginDto {
  @IsEmail()
  @ApiProperty()
  email: string;

  @ApiProperty()
  password: string;
}

export class ResetPasswordDto {
  @IsEmail()
  @ApiProperty()
  email: string;

  @ApiProperty()
  baseUrl: string;
}

export class ConfirmResetPasswordDto {
  @IsJWT()
  @ApiProperty()
  token: string;

  @ApiProperty()
  password: string;

  @ApiProperty()
  confirmPassword: string;
}
