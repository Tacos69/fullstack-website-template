import { HttpException, HttpStatus } from '@nestjs/common';

export class SamePasswordException extends HttpException {
  constructor() {
    super('The new password must be different from the old password', HttpStatus.BAD_REQUEST);
  }
}
