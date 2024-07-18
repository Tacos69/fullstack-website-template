import { Role } from 'src/enums/role.enum';

export interface User {
  userId: string;
  email: string;
  password: string;
  roles: Role[];
}
