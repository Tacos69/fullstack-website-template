import { Body, Controller, HttpCode, HttpStatus, Post, UseFilters } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() user: LoginDto) {
    return this.authService.login(user.email, user.password);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('register')
  register(@Body() user: RegisterDto) {
    return this.authService.register(user.email, user.password, user.confirmPassword);
  }
}
