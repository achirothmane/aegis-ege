terraform {
  required_version = "= 1.14.6"
}

variable "proof_value" {
  type = string
}

variable "effect_log" {
  type = string
}

resource "terraform_data" "governed" {
  input            = var.proof_value
  triggers_replace = var.proof_value

  provisioner "local-exec" {
    command = "printf '%s\\n' \"$PROOF_VALUE\" >> \"$EFFECT_LOG\""

    environment = {
      PROOF_VALUE = var.proof_value
      EFFECT_LOG  = var.effect_log
    }
  }
}

output "governed_value" {
  value = terraform_data.governed.output
}
