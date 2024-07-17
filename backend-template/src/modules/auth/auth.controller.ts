import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  Res,
  UseFilters,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ConfirmResetPasswordDto, LoginDto, RegisterDto, ResetPasswordDto } from './dto/auth.dto';
import { AuthGuard } from '../../guards/auth.guard';
import { Public } from 'src/decorators/public.decorator';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Public()
  @Post('login')
  login(@Body() user: LoginDto) {
    return this.authService.login(user.email, user.password);
  }

  @HttpCode(HttpStatus.CREATED)
  @Public()
  @Post('register')
  register(@Body() user: RegisterDto) {
    return this.authService.register(user.email, user.password, user.confirmPassword);
  }

  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @Post('reset-password')
  @Public()
  resetPassword(@Body() user: ResetPasswordDto) {
    return this.authService.requestResetPassword(user.email, user.baseUrl);
  }

  @Post('confirm-reset-password')
  @Public()
  confirmResetPassword(@Body() resetPassword: ConfirmResetPasswordDto) {
    return this.authService.resetPassword(
      resetPassword.token,
      resetPassword.password,
      resetPassword.confirmPassword,
    );
  }
}
