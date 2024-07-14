import { ApiProperty } from '@nestjs/swagger';
import { IsEmail } from 'class-validator';

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
