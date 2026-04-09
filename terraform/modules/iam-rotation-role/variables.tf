variable "environment"        { type = string }
variable "secret_path_prefix" { type = string }
variable "secret_arns"        { type = list(string) }
variable "kms_key_arns"       { type = list(string); default = [] }
variable "vpc_enabled"        { type = bool; default = true }
variable "tags"               { type = map(string); default = {} }
