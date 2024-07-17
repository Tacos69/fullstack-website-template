import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import * as bcrypt from 'bcrypt';
import { UserNotFoundException } from './exceptions/user-not-found.exception';
import { JwtService } from '@nestjs/jwt';
import { MailService } from '../mail/mail.service';
import { SamePasswordException } from './exceptions/same-password.exception';
import { TokenExpiredException } from './exceptions/token-expired.exception';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async login(email: string, password: string) {
    const user = await this.usersService.user({ email });
    if (!user) {
      throw new UserNotFoundException();
    }
    if (!(await bcrypt.compare(password, user.password))) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
    const payload = { sub: user.id };
    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async register(email: string, password: string, confirmPassword: string) {
    if (password !== confirmPassword) {
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }
    if (await this.usersService.user({ email })) {
      throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
    }
    const user = await this.usersService.createUser({
      email,
      password: await bcrypt.hash(password, 10),
    });
    const payload = { sub: user.id };
    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async requestResetPassword(email: string, baseUrl: string) {
    const user = await this.usersService.user({ email });
    if (!user) {
      return;
    }
    const payload = { email: user.email, sub: user.id };
    this.mailService.sendUserReset(
      email,
      baseUrl,
      await this.jwtService.signAsync(payload, {
        expiresIn: '5m',
        secret: process.env.RESET_SECRET,
      }),
    );
    return;
  }

  async resetPassword(token: string, password: string, confirmPassword: string) {
    if (password !== confirmPassword) {
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }
    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(token, { secret: process.env.RESET_SECRET });
    } catch (e) {
      throw new TokenExpiredException();
    }
    const user = await this.usersService.user({ id: payload.sub });
    if (!user) {
      throw new UserNotFoundException();
    }
    if (await bcrypt.compare(password, user.password)) {
      throw new SamePasswordException();
    }
    await this.usersService.updateUser({
      where: { id: user.id },
      data: { password: await bcrypt.hash(password, 10) },
    });
    return;
  }
}
