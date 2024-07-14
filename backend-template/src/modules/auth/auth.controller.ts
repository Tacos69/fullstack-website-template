import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UseFilters,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto/auth.dto';
import { AuthGuard } from '../../guards/auth.guard';
import { Public } from 'src/decorators/public.decorator';

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
}
