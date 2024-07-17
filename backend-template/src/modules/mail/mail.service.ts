import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendUserReset(email: string, baseUrl: string, token: string) {
    const url = `example.com/auth/reset-password?token=${token}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Reset your Password',
      template: './reset-password',
      context: {
        url: baseUrl + '?token=' + token,
      },
    });
  }
}
