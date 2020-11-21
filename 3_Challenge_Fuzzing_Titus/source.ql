import java

class ConstraintValidatorIsValidSource extends Method {
    ConstraintValidatorIsValidSource() {
        this.getName() = "isValid" 
        and this.getDeclaringType().getAnAncestor().getASupertype().getName() = "ConstraintValidator<>"
    }
}

from Method m
where m.overridesOrInstantiates(any(ConstraintValidatorIsValidSource t))
select m, "This is a validsource" 